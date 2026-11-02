using System.Security.Cryptography;
using System.Text;
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
/// Verifier-operator-owned, immutable tenant/key-successor pair inventory.
/// No HTTP request can register a pair, select an unapproved new DID or change
/// the HTTPS audience. A configuration file is NOT proof of trusted enrollment.
/// </summary>
internal sealed class HostPinnedIssuerSuccessorRegistry
{
    private static readonly HashSet<string> AllowedFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "TenantId", "PolicyId", "Audience", "TrustedPreviousIssuerDid",
        "PreapprovedSuccessorIssuerDid"
    };

    private readonly Dictionary<(Guid Tenant, string PolicyId), HostPinnedIssuerSuccessorPolicy>
        _policies = [];

    public HostPinnedIssuerSuccessorRegistry(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        IConfigurationSection root = configuration.GetSection("IssuerSuccessorTrust:Policies");
        if (root.Value is not null)
        {
            throw new InvalidOperationException("Invalid host-owned issuer successor inventory.");
        }

        IConfigurationSection[] entries = [.. root.GetChildren()];
        if (entries.Length > 128)
        {
            throw new InvalidOperationException("Too many host-owned issuer successor policies.");
        }

        foreach (IConfigurationSection entry in entries)
        {
            if (entry.Value is not null)
            {
                throw new InvalidOperationException("Invalid host-owned issuer successor policy structure.");
            }

            // A misspelled or nested security policy must never be ignored.
            foreach (IConfigurationSection field in entry.GetChildren())
            {
                if (!AllowedFields.Contains(field.Key) || field.Value is null ||
                    field.GetChildren().Any())
                {
                    throw new InvalidOperationException(
                        "Unknown, missing or nested host-owned issuer successor policy field.");
                }
            }

            string? tenantText = entry["TenantId"];
            string? policyId = entry["PolicyId"];
            string? audience = entry["Audience"];
            string? oldDid = entry["TrustedPreviousIssuerDid"];
            string? successorDid = entry["PreapprovedSuccessorIssuerDid"];
            if (!Guid.TryParse(tenantText, out Guid tenant) || tenant == Guid.Empty ||
                !IsPolicyId(policyId) || !ValidAudience(audience) ||
                oldDid is not { Length: > 0 and <= 255 } ||
                successorDid is not { Length: > 0 and <= 255 } ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(oldDid, out _) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(successorDid, out _) ||
                string.Equals(oldDid, successorDid, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Invalid host-owned issuer successor trust policy.");
            }

            if (!_policies.TryAdd((tenant, policyId!),
                    new HostPinnedIssuerSuccessorPolicy(audience!, oldDid, successorDid)))
            {
                throw new InvalidOperationException("Duplicate host-owned issuer successor policy.");
            }
        }
    }

    internal bool TryGet(Guid tenant, string policyId, out HostPinnedIssuerSuccessorPolicy? policy) =>
        _policies.TryGetValue((tenant, policyId), out policy);

    internal static bool IsPolicyId(string? value) =>
        value is { Length: > 0 and <= 64 } &&
        value.All(static character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2_000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);
}

internal sealed record HostPinnedIssuerSuccessorPolicy(
    string Audience, string TrustedPreviousIssuerDid, string PreapprovedSuccessorIssuerDid);

/// <summary>
/// Isolate host-pinned successor challenges from the older unpinned route and
/// from other operator policies (including future successor replacements).
/// The SDK expects its own purpose prefix; the adapter maps it to a separate
/// stable SHA-256 policy-bound namespace in the same existing PostgreSQL table.
/// </summary>
internal sealed class HostPinnedIssuerSuccessorChallengeStore : IPresentationChallengeStore
{
    private readonly IPresentationChallengeStore _inner;
    private readonly string _expectedAudience;
    private readonly string _storedPurpose;

    public HostPinnedIssuerSuccessorChallengeStore(
        IPresentationChallengeStore inner, string policyId,
        HostPinnedIssuerSuccessorPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(policyId);
        ArgumentNullException.ThrowIfNull(policy);
        _inner = inner;
        _expectedAudience = IssuerKeySuccessorAttestation.ChallengePurposePrefix + policy.Audience;

        string policyIdentity = string.Join("\n", policyId, policy.Audience,
            policy.TrustedPreviousIssuerDid, policy.PreapprovedSuccessorIssuerDid);
        _storedPurpose = "issuer-successor-host-pinned:" +
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(policyIdentity)));
    }

    public PresentationChallenge Issue(
        Guid verifierTenantId, string audience, string trustedIssuerDid,
        TimeSpan? lifetime = null) =>
        _inner.Issue(verifierTenantId, Scope(audience), trustedIssuerDid, lifetime);

    public PresentationChallenge? Find(
        Guid verifierTenantId, string audience, string nonce) =>
        _inner.Find(verifierTenantId, Scope(audience), nonce);

    public bool TryConsume(Guid verifierTenantId, string audience, string nonce) =>
        _inner.TryConsume(verifierTenantId, Scope(audience), nonce);

    /// <summary>
    /// Withdraw an exact host-owned policy challenge through the shared atomic
    /// store. Unknown, expired and already spent nonces are indistinguishable.
    /// This never modifies issuer trust or undoes accepted evidence.
    /// </summary>
    internal bool TryCancel(Guid verifierTenantId, string nonce) =>
        _inner.TryConsume(verifierTenantId, _storedPurpose, nonce);

    private string Scope(string audience)
    {
        if (!string.Equals(audience, _expectedAudience, StringComparison.Ordinal))
        {
            throw new ArgumentException("Unexpected issuer successor challenge scope.", nameof(audience));
        }

        return _storedPurpose;
    }
}

/// <summary>
/// An independently enrolled, verifier-operated alternative to the legacy
/// caller-selected issuer-successor challenge and key-control-only verifier.
/// It NEVER enrolls a DID or grants organisation/business authority.
/// </summary>
internal static class HostPinnedIssuerSuccessorHttpEndpoints
{
    private const int MaximumAttestationLength = 16_384;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-successor/host-pinned-challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("IssueHostPinnedIssuerSuccessorChallenge")
            .WithSummary("Issue a one-use issuer successor challenge from a verifier-host-owned key pair policy")
            .Produces<IssueIssuerSuccessorChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-successor/host-pinned-cancel", Cancel)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("CancelHostPinnedIssuerSuccessorChallenge")
            .WithSummary("Atomically withdraw a pending operator-pinned issuer successor challenge")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-successor/host-pinned-verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyHostPinnedIssuerSuccessor")
            .WithSummary("Require an operator-pinned successor DID and two genuine issuer signatures before atomic one-use admission")
            .Produces<VerifyIssuerSuccessorProofResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static IResult Issue(
        [FromBody] IssueHostPinnedIssuerSuccessorChallengeRequest request,
        [FromServices] HostPinnedIssuerSuccessorRegistry registry,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!HostPinnedIssuerSuccessorRegistry.IsPolicyId(request.PolicyId) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest();
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.PolicyId!, out HostPinnedIssuerSuccessorPolicy? policy) ||
            policy is null)
        {
            // Never disclose whether a policy belongs to another tenant.
            return InvalidRequest();
        }

        try
        {
            var scopedStore = new HostPinnedIssuerSuccessorChallengeStore(
                challenges, request.PolicyId!, policy);
            var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
                tenant, new Uri(policy.Audience, UriKind.Absolute),
                policy.TrustedPreviousIssuerDid, scopedStore,
                TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueIssuerSuccessorChallengeResponse(
                policy.Audience, challenge.Nonce, policy.TrustedPreviousIssuerDid,
                challenge.ExpiresAt), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidRequest();
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
    /// Operator-authorized incident cancellation for the exact verifier-owned
    /// policy namespace. No client-supplied issuer keys or audience are trusted.
    /// A 204 discloses neither challenge existence nor prior acceptance and
    /// cannot retroactively invalidate previously accepted continuity evidence.
    /// </summary>
    internal static IResult Cancel(
        [FromBody] CancelHostPinnedIssuerSuccessorChallengeRequest request,
        [FromServices] HostPinnedIssuerSuccessorRegistry registry,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!HostPinnedIssuerSuccessorRegistry.IsPolicyId(request.PolicyId) ||
            request.Nonce is not { Length: 43 } ||
            !request.Nonce.All(static character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))
        {
            return InvalidRequest();
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        // Missing and foreign policy IDs are no-ops to avoid an existence oracle.
        // The exact old/new DID pair, audience and purpose are pinned by the host,
        // not the HTTP request. The same shared atomic operation handles replay.
        if (!registry.TryGet(tenant, request.PolicyId!, out HostPinnedIssuerSuccessorPolicy? policy) ||
            policy is null)
        {
            return Results.NoContent();
        }

        try
        {
            var scopedStore = new HostPinnedIssuerSuccessorChallengeStore(
                challenges, request.PolicyId!, policy);
            _ = scopedStore.TryCancel(tenant, request.Nonce);
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
        [FromBody] VerifyHostPinnedIssuerSuccessorProofRequest request,
        [FromServices] HostPinnedIssuerSuccessorRegistry registry,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!HostPinnedIssuerSuccessorRegistry.IsPolicyId(request.PolicyId) ||
            request.Attestation is not { Length: > 0 and <= MaximumAttestationLength } ||
            request.Nonce is not { Length: 43 } ||
            !request.Nonce.All(static character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))
        {
            return InvalidRequest();
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.PolicyId!, out HostPinnedIssuerSuccessorPolicy? policy) ||
            policy is null)
        {
            // An absent or foreign operator pin is indistinguishable from an
            // invalid proof and cannot consume any shared challenge.
            return InvalidProof();
        }

        try
        {
            var scopedStore = new HostPinnedIssuerSuccessorChallengeStore(
                challenges, request.PolicyId!, policy);
            bool valid = IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
                request.Attestation, policy.TrustedPreviousIssuerDid,
                policy.PreapprovedSuccessorIssuerDid, new Uri(policy.Audience, UriKind.Absolute),
                request.Nonce, tenant, scopedStore, clock, out string successorDid);
            return Results.Ok(new VerifyIssuerSuccessorProofResponse(
                valid ? "ValidPinnedKeyContinuity" : "Invalid",
                valid ? successorDid : null));
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

    private static IResult InvalidProof() =>
        Results.Ok(new VerifyIssuerSuccessorProofResponse("Invalid", null));

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Host-Pinned Issuer Successor Request",
        detail: "A registered verifier policy, bounded proof and valid one-use challenge are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume a one-use successor challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>Only the operator-owned policy ID is selected; no keys or audience in the request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IssueHostPinnedIssuerSuccessorChallengeRequest
{
    public string? PolicyId { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>Operator's scoped one-use cancellation, without caller-selected trust keys.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CancelHostPinnedIssuerSuccessorChallengeRequest
{
    public string? PolicyId { get; init; }
    public string? Nonce { get; init; }
}

/// <summary>Trust pins and HTTPS audience are never accepted from HTTP clients.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class VerifyHostPinnedIssuerSuccessorProofRequest
{
    public string? PolicyId { get; init; }
    public string? Attestation { get; init; }
    public string? Nonce { get; init; }
}
