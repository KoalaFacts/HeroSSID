using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.DidOperations.DidMethods;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated HTTP verifier of the original VC1.1 issuer statement and
/// independent holder proof. Verifier trust is retained in a durable, tenant
/// scoped single-use challenge and never derived from the holder's JWT.
/// </summary>
internal static class JwtVcJsonPresentationEndpoints
{
    private const int MaximumPresentationLength = 131_072;
    private const int MaximumSnapshotLength = 65_536;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/presentation-challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("IssueJwtVcJsonPresentationChallenge")
            .WithSummary("Issue a tenant-bound, one-use VC1.1 verifier challenge")
            .Produces<IssueJwtVcJsonPresentationChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/jwt-vc-json/verify-presentation", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonPresentation")
            .WithSummary("Verify VC1.1 original issuer and holder signatures, one-use proof and issuer-signed status")
            .Produces<VerifyJwtVcJsonPresentationResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// Only an authenticated verifier tenant may choose its trusted issuer and
    /// exact HTTPS audience. The returned challenge is unsigned; the verifier
    /// must separately authenticate its request to the holder with its OWN key.
    /// </summary>
    internal static IResult Issue(
        [FromBody] IssueJwtVcJsonPresentationChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.TrustedIssuerDid) ||
            request.TrustedIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.TrustedIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidChallenge();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var challenge = challenges.Issue(tenantId, request.Audience!,
                request.TrustedIssuerDid!, TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueJwtVcJsonPresentationChallengeResponse(
                challenge.Audience, challenge.Nonce, challenge.TrustedIssuerDid,
                challenge.ExpiresAt), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidChallenge();
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached the retained challenge capacity.",
                statusCode: StatusCodes.Status429TooManyRequests);
        }
        catch (NpgsqlException)
        {
            return Unavailable();
        }
        catch (TimeoutException)
        {
            return Unavailable();
        }
    }

    /// <summary>
    /// The issuer trust policy comes from durable verifier state, not the
    /// submitted holder proof or status JWT. An authentic holder proof consumes
    /// its challenge even when the original issuer later denies status.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyJwtVcJsonPresentationRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (string.IsNullOrWhiteSpace(request.Presentation) ||
            request.Presentation.Length > MaximumPresentationLength ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumSnapshotLength ||
            !ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.Nonce.Length != 43 ||
            !ValidCredentialType(request.ExpectedCredentialType) ||
            !ValidContext(request.SubjectContextUri))
        {
            return Results.Problem(title: "Invalid VC1.1 Presentation Request",
                detail: "A bounded holder VP, issuer-signed status, original nonce, exact HTTPS audience and pinned credential vocabulary are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var status = JwtVcJsonRevocationSnapshot.CheckPresentation(
                request.Presentation!, request.RevocationSnapshot!, tenantId,
                request.Audience!, request.Nonce!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, challenges, clock, out var subject);
            return status switch
            {
                RevocationSnapshotCheckResult.NotListed =>
                    Results.Ok(new VerifyJwtVcJsonPresentationResponse("SignedNotListed", subject)),
                RevocationSnapshotCheckResult.Revoked =>
                    Results.Ok(new VerifyJwtVcJsonPresentationResponse("Revoked", null)),
                _ => Results.Ok(new VerifyJwtVcJsonPresentationResponse("Invalid", null))
            };
        }
        catch (NpgsqlException)
        {
            return Unavailable();
        }
        catch (TimeoutException)
        {
            return Unavailable();
        }
    }

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2048 &&
        Uri.TryCreate(audience, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static bool ValidCredentialType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        Uri.TryCreate(type, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 && uri.UserInfo.Length == 0;

    private static bool ValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2048;

    private static IResult InvalidChallenge() => Results.Problem(
        title: "Invalid VC1.1 Challenge Request",
        detail: "An exact HTTPS verifier audience, real trusted Ed25519 issuer did:key and lifetime of 1–300 seconds are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume its durable one-use challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>The caller chooses the trusted issuer; a wallet cannot replace that policy.</summary>
public sealed class IssueJwtVcJsonPresentationChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>An unsigned nonce that an independent verifier must authenticate to a holder.</summary>
public sealed record IssueJwtVcJsonPresentationChallengeResponse(
    string Audience, string Nonce, string TrustedIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>The policy is provided by the authorized verifier, not by the holder proof.</summary>
public sealed class VerifyJwtVcJsonPresentationRequest
{
    public string? Presentation { get; init; }
    public string? RevocationSnapshot { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>SignedNotListed does not prove live non-revocation, identity or authorization.</summary>
public sealed record VerifyJwtVcJsonPresentationResponse(string Status, JsonElement? VerifiedSubject);
