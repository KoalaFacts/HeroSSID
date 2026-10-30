using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.DidOperations.DidMethods;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated, verifier-owned one-time check that two different issuer
/// did:key controllers signed the same successor statement. This does not
/// enroll either key, update issuer trust, recover lost keys or grant authority.
/// </summary>
internal static class IssuerSuccessorEndpoints
{
    // Separate the challenge-store purpose from VC presentation challenges:
    // a proof from either workflow cannot consume the other's nonce.
    private const string PurposePrefix = "issuer-successor:";
    private const int MaximumAttestationLength = 16_384;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-successor/challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("IssueIssuerSuccessorChallenge")
            .WithSummary("Issue a verifier-owned one-time challenge for a dual-signed issuer did:key successor proof")
            .Produces<IssueIssuerSuccessorChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-successor/verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyIssuerSuccessorProof")
            .WithSummary("Verify both issuer keys and atomically consume the verifier-owned successor challenge")
            .Produces<VerifyIssuerSuccessorProofResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// The authenticated verifier chooses the PREVIOUS issuer it independently
    /// trusts. This issues a nonce, not a statement of successor authorization.
    /// </summary>
    internal static IResult Issue(
        [FromBody] IssueIssuerSuccessorChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.PreviousIssuerDid) ||
            request.PreviousIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.PreviousIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest("A canonical HTTPS verifier audience, previous Ed25519 did:key and 1–300 second lifetime are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var challenge = challenges.Issue(
                tenantId, StoredAudience(request.Audience!), request.PreviousIssuerDid!,
                TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueIssuerSuccessorChallengeResponse(
                request.Audience!, challenge.Nonce, challenge.TrustedIssuerDid,
                challenge.ExpiresAt), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The issuer successor challenge is invalid.");
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached its retained one-time challenge capacity.",
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
    /// The previous issuer DID comes from verifier-owned durable state, never
    /// from the supplied signed artifact. Only authentic two-key evidence may
    /// spend the nonce. Returning a proposed successor is NOT trust promotion.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyIssuerSuccessorProofRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (string.IsNullOrWhiteSpace(request.Attestation) ||
            request.Attestation.Length > MaximumAttestationLength ||
            !ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.Nonce.Length != 43)
        {
            return InvalidRequest("A bounded dual-signed attestation, exact HTTPS audience and issued nonce are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        string storedAudience = StoredAudience(request.Audience!);
        try
        {
            var issued = challenges.Find(tenantId, storedAudience, request.Nonce!);
            if (issued is null ||
                !IssuerKeySuccessorAttestation.TryVerify(
                    request.Attestation!, issued.TrustedIssuerDid, new Uri(request.Audience!),
                    request.Nonce!, clock.GetUtcNow(), out string successorDid) ||
                !challenges.TryConsume(tenantId, storedAudience, request.Nonce!))
            {
                return Results.Ok(new VerifyIssuerSuccessorProofResponse("Invalid", null));
            }

            return Results.Ok(new VerifyIssuerSuccessorProofResponse(
                "ValidKeyContinuity", successorDid));
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

    private static string StoredAudience(string audience) => PurposePrefix + audience;

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult InvalidRequest(string detail) => Results.Problem(
        title: "Invalid Issuer Successor Request", detail: detail,
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume a one-time successor challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>Verifier policy, not an issuer claim; no key or trust-list mutation.</summary>
public sealed class IssueIssuerSuccessorChallengeRequest
{
    public string? Audience { get; init; }
    public string? PreviousIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>The nonce is unsigned; an issuer must pin and authenticate the verifier separately.</summary>
public sealed record IssueIssuerSuccessorChallengeResponse(
    string Audience, string Nonce, string TrustedPreviousIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Complete original dual-signed artifact, without any supplied trusted-issuer override.</summary>
public sealed class VerifyIssuerSuccessorProofRequest
{
    public string? Attestation { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
}

/// <summary>ValidKeyContinuity proves two keys signed, never issuer enrollment or business authority.</summary>
public sealed record VerifyIssuerSuccessorProofResponse(string Status, string? SuccessorIssuerDid);
