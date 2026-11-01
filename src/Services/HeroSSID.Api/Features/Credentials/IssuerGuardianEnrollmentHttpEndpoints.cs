using HeroSSID.Api.Authentication;
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
/// Authenticated, non-.NET caller adapter for exact old-issuer-signed guardian
/// enrollment evidence. The caller supplies pre-incident trusted policy; this
/// service never registers a guardian or promotes a recovered DID.
/// </summary>
internal static class IssuerGuardianEnrollmentHttpEndpoints
{
    private const int MaximumEnrollmentJwtLength = 4_096;
    private const int MaximumEvidenceLength = 32_768;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-guardian-recovery/enrolled-challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("IssueExactEnrolledGuardianRecoveryChallenge")
            .WithSummary("Issue a recovery challenge bound to an exact prior-approved signed guardian policy")
            .Produces<IssueExactEnrolledGuardianRecoveryChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-guardian-recovery/enrolled-verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyExactEnrolledGuardianRecovery")
            .WithSummary("Verify an exact old-issuer enrollment, successor and guardian signatures, then atomically consume its nonce")
            .Produces<VerifyIssuerGuardianRecoveryResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static IResult Issue(
        [FromBody] IssueExactEnrolledGuardianRecoveryChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidAudience(request.Audience) ||
            !ValidDid(request.TrustedPreviousIssuerDid) ||
            !ValidEnrollment(request.SignedEnrollmentJwt, request.IndependentlyPinnedSha256) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            // The authenticated relying-party backend MUST obtain these values
            // from its independently approved pre-incident trust records.
            // Supplying a matching hash on this request is not enrollment proof.
            PresentationChallenge issued = IssuerGuardianRecoveryEnrollment.IssueChallenge(
                challenges, tenantId, request.SignedEnrollmentJwt!,
                request.IndependentlyPinnedSha256!, request.TrustedPreviousIssuerDid!,
                new Uri(request.Audience!), clock,
                TimeSpan.FromSeconds(request.LifetimeSeconds));

            return Results.Json(new IssueExactEnrolledGuardianRecoveryChallengeResponse(
                request.Audience!, issued.Nonce, request.TrustedPreviousIssuerDid!,
                issued.ExpiresAt, ExactEnrollmentBound: true),
                statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            // Malformed, expired, forged or non-matching old-issuer enrollment.
            // Never disclose which trust-policy check rejected it.
            return InvalidRequest();
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached its one-use challenge capacity.",
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

    internal static IResult Verify(
        [FromBody] VerifyExactEnrolledGuardianRecoveryRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidAudience(request.Audience) ||
            !ValidDid(request.TrustedPreviousIssuerDid) ||
            !ValidEnrollment(request.SignedEnrollmentJwt, request.IndependentlyPinnedSha256) ||
            !ValidNonce(request.Nonce) ||
            string.IsNullOrWhiteSpace(request.EvidenceJson) ||
            request.EvidenceJson.Length > MaximumEvidenceLength)
        {
            return InvalidRequest();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            // The SDK checks the original old-key signature AND exact JWT pin
            // again before checking all guardian/new-key Ed25519 signatures.
            // Only an atomic, purpose-bound shared-store consumption can
            // release the candidate DID. This proves no business authority.
            bool accepted = IssuerGuardianRecoveryEnrollment.TryVerifyAndConsume(
                challenges, tenantId, request.EvidenceJson!,
                request.SignedEnrollmentJwt!, request.IndependentlyPinnedSha256!,
                request.TrustedPreviousIssuerDid!, new Uri(request.Audience!),
                request.Nonce!, clock, out string candidate);

            return Results.Ok(new VerifyIssuerGuardianRecoveryResponse(
                accepted ? "ValidRecoveryEvidence" : "Invalid",
                accepted ? candidate : null));
        }
        catch (ArgumentException)
        {
            // A well-shaped but rejected cryptographic payload is not a
            // source of authorization or detailed public error information.
            return Results.Ok(new VerifyIssuerGuardianRecoveryResponse("Invalid", null));
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

    private static bool ValidEnrollment(string? signed, string? digest) =>
        signed is { Length: > 0 and <= MaximumEnrollmentJwtLength } &&
        digest is { Length: 64 } &&
        digest.All(static c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= 255 &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _);

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2_000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static bool ValidNonce(string? nonce) =>
        nonce is { Length: 43 } &&
        nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Pre-Enrolled Guardian Recovery Request",
        detail: "An exact HTTPS audience, pinned old issuer, original signed guardian enrollment, uppercase SHA-256 fingerprint and bounded nonce or lifetime are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume the recovery challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>
/// Independently approved pin and JWT must be loaded by the caller from its
/// pre-incident trust inventory; a caller-provided digest is not proof of approval.
/// </summary>
public sealed class IssueExactEnrolledGuardianRecoveryChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
    public string? SignedEnrollmentJwt { get; init; }
    public string? IndependentlyPinnedSha256 { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>A pending challenge, not a proof of enrollment or permission to recover.</summary>
public sealed record IssueExactEnrolledGuardianRecoveryChallengeResponse(
    string Audience, string Nonce, string TrustedPreviousIssuerDid,
    DateTimeOffset ExpiresAt, bool ExactEnrollmentBound);

/// <summary>
/// Signed cryptographic recovery evidence under the exact previously enrolled
/// policy; only the relying party can decide actual recovery authority.
/// </summary>
public sealed class VerifyExactEnrolledGuardianRecoveryRequest
{
    public string? EvidenceJson { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
    public string? SignedEnrollmentJwt { get; init; }
    public string? IndependentlyPinnedSha256 { get; init; }
}
