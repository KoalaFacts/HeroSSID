using System.Text.Json.Serialization;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// A verifier-operator-owned, immutable pre-incident enrollment inventory.
/// No authenticated HTTP request can add to or replace this inventory.
/// </summary>
internal sealed class HostPinnedGuardianEnrollmentRegistry
{
    private const string EmergencyDenialsKey = "IssuerGuardianEnrollmentTrust:RevokedSha256";
    private readonly IConfiguration _configuration;
    private readonly Dictionary<(Guid Tenant, string Issuer, string Audience), HostPinnedGuardianEnrollment> _registrations = [];

    public HostPinnedGuardianEnrollmentRegistry(IConfiguration configuration, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(clock);
        _configuration = configuration;

        // A malformed emergency denial list must not be silently ignored on
        // startup. Later reloads fail closed in TryGet without crashing the host.
        if (!TryReadEmergencyDenials(configuration, null, out _))
        {
            throw new InvalidOperationException("Invalid host-pinned guardian emergency revocation configuration.");
        }

        var entries = configuration.GetSection("IssuerGuardianEnrollmentTrust:Registrations").GetChildren().ToArray();
        DateTimeOffset now = clock.GetUtcNow();
        if (entries.Length > 256)
        {
            throw new InvalidOperationException("The host-pinned guardian enrollment inventory exceeds 256 records.");
        }

        foreach (IConfigurationSection entry in entries)
        {
            string? tenantText = entry["TenantId"];
            string? issuer = entry["TrustedPreviousIssuerDid"];
            string? audience = entry["Audience"];
            string? jwt = entry["SignedEnrollmentJwt"];
            string? fingerprint = entry["ApprovedSha256"];
            if (!Guid.TryParse(tenantText, out Guid tenant) || tenant == Guid.Empty ||
                string.IsNullOrWhiteSpace(issuer) || issuer.Length > 255 ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuer, out _) ||
                !HostPinnedIssuerGuardianRecoveryHttpEndpoints.ValidAudience(audience) ||
                jwt is not { Length: > 0 and <= 4_096 } ||
                fingerprint is not { Length: 64 } ||
                fingerprint.Any(static c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            {
                // Configuration is security-sensitive: never silently omit a broken record.
                throw new InvalidOperationException("Invalid host-pinned guardian enrollment configuration.");
            }

            // Startup must authenticate the operator's entire signed policy,
            // not just its shape: invalid pins, forged old-issuer signatures,
            // wrong audiences and inactive policies must never reach a live host.
            // This does not independently prove that the operator approved
            // the configuration before an issuer-key-loss incident.
            if (!IssuerGuardianRecoveryEnrollment.TryVerify(
                    jwt, issuer, fingerprint, new Uri(audience!, UriKind.Absolute),
                    now, out _, out _))
            {
                throw new InvalidOperationException(
                    "Invalid signed host-pinned guardian enrollment configuration.");
            }

            var key = (tenant, issuer, audience!);
            if (!_registrations.TryAdd(key, new HostPinnedGuardianEnrollment(jwt, fingerprint)))
            {
                throw new InvalidOperationException("Duplicate host-pinned guardian enrollment registration.");
            }
        }
    }

    internal bool TryGet(Guid tenantId, string oldIssuerDid, string audience,
        out HostPinnedGuardianEnrollment? registration)
    {
        registration = null;
        if (!_registrations.TryGetValue((tenantId, oldIssuerDid, audience),
                out HostPinnedGuardianEnrollment? approved) ||
            !TryReadEmergencyDenials(_configuration, approved.ApprovedSha256, out bool revoked) ||
            revoked)
        {
            // Neither a revoked policy nor malformed operator configuration
            // may cause a new challenge or redeem an outstanding one.
            return false;
        }

        registration = approved;
        return true;
    }

    private static bool TryReadEmergencyDenials(
        IConfiguration configuration, string? fingerprint, out bool revoked)
    {
        revoked = false;
        IConfigurationSection section = configuration.GetSection(EmergencyDenialsKey);
        // Reject a scalar or nested/ambiguous value instead of accidentally
        // interpreting a malformed revocation policy as an empty list.
        if (section.Value is not null)
        {
            return false;
        }

        IConfigurationSection[] entries = [.. section.GetChildren()];
        if (entries.Length > 256)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (IConfigurationSection entry in entries)
        {
            string? digest = entry.Value;
            if (digest is not { Length: 64 } ||
                digest.Any(static c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')) ||
                !seen.Add(digest))
            {
                return false;
            }

            if (string.Equals(digest, fingerprint, StringComparison.Ordinal))
            {
                revoked = true;
            }
        }

        return true;
    }
}

internal sealed record HostPinnedGuardianEnrollment(string SignedEnrollmentJwt, string ApprovedSha256);

/// <summary>
/// Optional HTTP adapter whose signed guardian recovery policy is selected
/// exclusively from the host's independently configured pre-incident inventory.
/// Authenticated callers cannot select their own JWT or fingerprint as trust.
/// </summary>
internal static class HostPinnedIssuerGuardianRecoveryHttpEndpoints
{
    private const int MaximumEvidenceLength = 32_768;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-guardian-recovery/host-pinned-challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("IssueHostPinnedGuardianRecoveryChallenge")
            .WithSummary("Issue a recovery challenge using the verifier host's pre-incident guardian enrollment")
            .Produces<IssueExactEnrolledGuardianRecoveryChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-guardian-recovery/host-pinned-verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyHostPinnedGuardianRecovery")
            .WithSummary("Verify a successor and original guardian roster from the verifier's own stored enrollment")
            .Produces<VerifyIssuerGuardianRecoveryResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static IResult Issue(
        [FromBody] IssueHostPinnedGuardianRecoveryChallengeRequest request,
        [FromServices] HostPinnedGuardianEnrollmentRegistry registry,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidSelector(request.TrustedPreviousIssuerDid, request.Audience) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest();
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.TrustedPreviousIssuerDid!, request.Audience!,
                out HostPinnedGuardianEnrollment? policy) || policy is null)
        {
            // Do not distinguish absent, foreign-tenant or wrong-issuer pins.
            return InvalidRequest();
        }

        try
        {
            PresentationChallenge challenge = IssuerGuardianRecoveryEnrollment.IssueChallenge(
                challenges, tenant, policy.SignedEnrollmentJwt, policy.ApprovedSha256,
                request.TrustedPreviousIssuerDid!, new Uri(request.Audience!), clock,
                TimeSpan.FromSeconds(request.LifetimeSeconds));

            return Results.Json(new IssueExactEnrolledGuardianRecoveryChallengeResponse(
                request.Audience!, challenge.Nonce, request.TrustedPreviousIssuerDid!,
                challenge.ExpiresAt, ExactEnrollmentBound: true),
                statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
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
        [FromBody] VerifyHostPinnedGuardianRecoveryRequest request,
        [FromServices] HostPinnedGuardianEnrollmentRegistry registry,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidSelector(request.TrustedPreviousIssuerDid, request.Audience) ||
            request.Nonce is not { Length: 43 } ||
            !request.Nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ||
            string.IsNullOrWhiteSpace(request.EvidenceJson) ||
            request.EvidenceJson.Length > MaximumEvidenceLength)
        {
            return InvalidRequest();
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.TrustedPreviousIssuerDid!, request.Audience!,
                out HostPinnedGuardianEnrollment? policy) || policy is null)
        {
            return InvalidEvidence();
        }

        try
        {
            bool valid = IssuerGuardianRecoveryEnrollment.TryVerifyAndConsume(
                challenges, tenant, request.EvidenceJson!, policy.SignedEnrollmentJwt,
                policy.ApprovedSha256, request.TrustedPreviousIssuerDid!,
                new Uri(request.Audience!), request.Nonce!, clock,
                out string candidateSuccessorDid);

            return Results.Ok(new VerifyIssuerGuardianRecoveryResponse(
                valid ? "ValidRecoveryEvidence" : "Invalid",
                valid ? candidateSuccessorDid : null));
        }
        catch (ArgumentException)
        {
            return InvalidEvidence();
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

    private static bool ValidSelector(string? previousIssuerDid, string? audience) =>
        !string.IsNullOrWhiteSpace(previousIssuerDid) &&
        previousIssuerDid.Length <= 255 &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(previousIssuerDid, out _) &&
        ValidAudience(audience);

    internal static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2_000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Host-Pinned Guardian Recovery Request",
        detail: "A valid HTTPS audience and issuer with an operator-registered pre-incident policy are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult InvalidEvidence() =>
        Results.Ok(new VerifyIssuerGuardianRecoveryResponse("Invalid", null));

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume the recovery challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>
/// No signed JWT or digest is accepted in this request; those must already be
/// provisioned by the verifier operator from its independent trust inventory.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IssueHostPinnedGuardianRecoveryChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>
/// An authenticated caller presents signed recovery evidence but cannot choose
/// the original guardian policy, its old-issuer signature or its approved pin.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class VerifyHostPinnedGuardianRecoveryRequest
{
    public string? Audience { get; init; }
    public string? TrustedPreviousIssuerDid { get; init; }
    public string? Nonce { get; init; }
    public string? EvidenceJson { get; init; }
}
