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
/// Authenticated HTTP adapter for verifier-owned issuer guardian recovery.
/// This is independently pinned signature evidence, not DID trust promotion,
/// identity vetting, holder control or organization/business authorization.
/// </summary>
internal static class IssuerGuardianRecoveryHttpEndpoints
{
    private const int MaximumEvidenceLength = 32_768;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-guardian-recovery/challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("IssueIssuerGuardianRecoveryChallenge")
            .WithSummary("Issue a tenant-bound one-use guardian recovery challenge; no issuer trust change")
            .Produces<IssueIssuerGuardianRecoveryChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-guardian-recovery/cancel", Cancel)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("CancelIssuerGuardianRecoveryChallenge")
            .WithSummary("Invalidate a pending one-use guardian recovery challenge without disclosing whether it exists")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-guardian-recovery/verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyIssuerGuardianRecoveryEvidence")
            .WithSummary("Verify independent successor and guardian Ed25519 signatures and atomically consume a recovery challenge")
            .Produces<VerifyIssuerGuardianRecoveryResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static IResult Issue(
        [FromBody] IssueIssuerGuardianRecoveryChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        bool policyBound = request.TrustedGuardianDids is not null ||
            request.RequiredGuardianSignatures.HasValue;
        if (!ValidAudience(request.Audience) || !ValidDid(request.PreviousIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300 ||
            (policyBound && (!request.RequiredGuardianSignatures.HasValue ||
                !ValidGuardianPolicy(request.TrustedGuardianDids, request.PreviousIssuerDid!,
                    request.RequiredGuardianSignatures.Value))))
        {
            return InvalidRequest("An exact HTTPS audience, old Ed25519 issuer, 1–300 second lifetime and (when supplied) a complete, distinct guardian quorum policy are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            PresentationChallenge issued = policyBound
                ? IssuerGuardianRecoveryChallenges.IssueBoundToGuardians(
                    challenges, tenantId, request.PreviousIssuerDid!,
                    request.TrustedGuardianDids!, request.RequiredGuardianSignatures!.Value,
                    new Uri(request.Audience!), TimeSpan.FromSeconds(request.LifetimeSeconds))
                : IssuerGuardianRecoveryChallenges.Issue(
                    challenges, tenantId, request.PreviousIssuerDid!,
                    new Uri(request.Audience!), TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueIssuerGuardianRecoveryChallengeResponse(
                request.Audience!, issued.Nonce, request.PreviousIssuerDid!,
                issued.ExpiresAt, policyBound), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The guardian recovery challenge is invalid.");
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

    /// <summary>
    /// Withdraw a pending incident challenge using verifier-owned tenant, old
    /// issuer and recovery purpose. Return the same empty response for unknown,
    /// expired or already consumed nonces to avoid a challenge existence oracle.
    /// A 204 never retroactively reverses previously accepted evidence.
    /// </summary>
    internal static IResult Cancel(
        [FromBody] CancelIssuerGuardianRecoveryChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) || !ValidDid(request.TrustedPreviousIssuerDid) ||
            request.Nonce is not { Length: 43 } ||
            !request.Nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            return InvalidRequest("An exact HTTPS audience, pinned old issuer DID and issued nonce are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            _ = IssuerGuardianRecoveryChallenges.TryCancel(
                challenges, tenantId, request.TrustedPreviousIssuerDid!,
                new Uri(request.Audience!), request.Nonce);
            return Results.NoContent();
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
        [FromBody] VerifyIssuerGuardianRecoveryRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (string.IsNullOrWhiteSpace(request.EvidenceJson) ||
            request.EvidenceJson.Length > MaximumEvidenceLength ||
            !ValidAudience(request.Audience) ||
            request.Nonce is not { Length: 43 } ||
            !ValidDid(request.TrustedPreviousIssuerDid) ||
            !ValidGuardianPolicy(request.TrustedGuardianDids,
                request.TrustedPreviousIssuerDid!, request.RequiredGuardianSignatures))
        {
            return InvalidRequest("A bounded signed recovery envelope, issued nonce, exact HTTPS audience, pinned old issuer and independent 2–5 guardian DID policy are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            // All trust pins are authenticated CALLER policy, never enrolled from
            // proof claims. The shared store independently authenticates the
            // original tenant, purpose, old issuer, audience and one-use nonce.
            bool accepted = IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
                challenges, tenantId, request.EvidenceJson!,
                request.TrustedPreviousIssuerDid!, request.TrustedGuardianDids!,
                request.RequiredGuardianSignatures, new Uri(request.Audience!),
                request.Nonce!, clock, out string candidate);
            return Results.Ok(new VerifyIssuerGuardianRecoveryResponse(
                accepted ? "ValidRecoveryEvidence" : "Invalid",
                accepted ? candidate : null));
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

    private static bool ValidGuardianPolicy(
        IReadOnlyCollection<string>? guardians, string previousIssuer, int required)
    {
        if (guardians is null || guardians.Count is < 2 or > 5 ||
            required < 2 || required > guardians.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in guardians)
        {
            if (!ValidDid(did) ||
                string.Equals(did, previousIssuer, StringComparison.Ordinal) ||
                !unique.Add(did))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= 255 &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _);

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2_000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult InvalidRequest(string detail) => Results.Problem(
        title: "Invalid Guardian Recovery Request", detail: detail,
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume the guardian recovery challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>A caller-authorized recovery request, not a server-issued claim of incident authority.</summary>
public sealed class IssueIssuerGuardianRecoveryChallengeRequest
{
    public string? Audience { get; init; }
    public string? PreviousIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;

    /// <summary>Optional pre-enrolled guardian pins to commit at issuance, never learned from proof.</summary>
    public IReadOnlyCollection<string>? TrustedGuardianDids { get; init; }

    /// <summary>Required signatures in the pinned guardian set, supplied together with pins.</summary>
    public int? RequiredGuardianSignatures { get; init; }
}

/// <summary>Unverified challenge metadata; the signer must authenticate its origin out of band.</summary>
public sealed record IssueIssuerGuardianRecoveryChallengeResponse(
    string Audience, string Nonce, string TrustedPreviousIssuerDid, DateTimeOffset ExpiresAt,
    bool GuardianPolicyBound);

/// <summary>
/// Exact verifier-owned incident challenge to withdraw; this request never
/// enrolls guardians, transfers DID control or authorizes recovery.
/// </summary>
public sealed class CancelIssuerGuardianRecoveryChallengeRequest
{
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
}

/// <summary>
/// Explicit caller-owned pre-enrolled guardian policy. The server does not
/// independently register or authorize guardians from this request.
/// </summary>
public sealed class VerifyIssuerGuardianRecoveryRequest
{
    public string? EvidenceJson { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
    public IReadOnlyCollection<string>? TrustedGuardianDids { get; init; }
    public int RequiredGuardianSignatures { get; init; }
}

/// <summary>A cryptographic quorum result; never a DID transfer or authorization decision.</summary>
public sealed record VerifyIssuerGuardianRecoveryResponse(string Status, string? SuccessorIssuerDid);
