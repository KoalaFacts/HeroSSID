using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated, verifier-owned single-use VC2 presentation boundary.
/// An issuer's signed claim, holder's key proof and issuer status are checked separately.
/// </summary>
internal static class Vcdm20PresentationEndpoints
{
    private const int MaximumPresentationLength = 131_072;
    private const int MaximumSnapshotLength = 65_536;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/vcdm20/presentation-challenge", Issue)
            .RequireAuthorization("credential:verify")
            .WithName("IssueVcdm20PresentationChallenge")
            .WithSummary("Create a verifier-owned, one-use VC2 challenge for a signed holder request")
            .Produces<IssueVcdm20PresentationChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/vcdm20/verify-presentation", Verify)
            .RequireAuthorization("credential:verify")
            .WithName("VerifyVcdm20Presentation")
            .WithSummary("Check issuer and holder Ed25519 signatures, replay and signed VC2 status")
            .Produces<VerifyVcdm20PresentationResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// The authenticated verifier tenant chooses the issuer it trusts for this request.
    /// It signs the returned challenge with its OWN independent did:key signer before
    /// showing the request to a holder; issuing a nonce does not establish verifier identity.
    /// </summary>
    internal static IResult Issue(
        [FromBody] IssueVcdm20PresentationChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(request.TrustedIssuerDid!, out _) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return BadChallenge();
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
            return Results.Json(new IssueVcdm20PresentationChallengeResponse(
                challenge.Audience, challenge.Nonce, challenge.TrustedIssuerDid, challenge.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return BadChallenge();
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
    /// The challenge's tenant, audience, nonce and issuer policy come from the verifier
    /// store, never from the holder token. Claims are released only after authentic issuer
    /// AND holder signatures, one-use consumption and an issuer-signed status snapshot.
    /// SignedNotListed is not proof of live non-revocation or business authorization.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyVcdm20PresentationRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        Uri? context = request.SubjectContextUri;
        if (string.IsNullOrWhiteSpace(request.Presentation) ||
            request.Presentation.Length > MaximumPresentationLength ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumSnapshotLength ||
            !ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.Nonce.Length != 43 ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.ExpectedCredentialType.Length > 128 ||
            request.ExpectedCredentialType.Any(char.IsWhiteSpace) ||
            context is null || !context.IsAbsoluteUri ||
            !string.Equals(context.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(context.UserInfo) ||
            !string.IsNullOrEmpty(context.Fragment) ||
            context.AbsoluteUri.Length > 2048)
        {
            return Results.Problem(title: "Invalid Presentation Request",
                detail: "A bounded presentation, authentic issuer status, exact issued nonce and pinned HTTPS policy are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var status = Vcdm20RevocationSnapshot.CheckPresentation(
                request.Presentation, request.RevocationSnapshot, tenantId, request.Audience!,
                request.Nonce!, request.ExpectedCredentialType!, context,
                challenges, clock, out var subject);
            return Results.Ok(new VerifyVcdm20PresentationResponse(
                status.ToString(),
                status == Vcdm20RevocationCheckResult.SignedNotListed ? subject : null));
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
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult BadChallenge() => Results.Problem(
        title: "Invalid Challenge Request",
        detail: "An exact HTTPS verifier audience, valid Ed25519 did:key issuer and lifetime between 1 and 300 seconds are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The presentation could not be verified using durable challenge state.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>Only the verifier chooses and retains trusted issuer and challenge audience.</summary>
public sealed class IssueVcdm20PresentationChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>Verifiers must sign this challenge with an independently held verifier key.</summary>
public sealed record IssueVcdm20PresentationChallengeResponse(
    string Audience, string Nonce, string TrustedIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Caller pins claim vocabulary and type; the server retains issuer policy.</summary>
public sealed class VerifyVcdm20PresentationRequest
{
    public string? Presentation { get; init; }
    public string? RevocationSnapshot { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>Only SignedNotListed returns verified claims; it never grants authorization.</summary>
public sealed record VerifyVcdm20PresentationResponse(string Status, JsonElement? VerifiedSubject);
