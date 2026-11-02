using System.Globalization;
using System.Text.Json.Serialization;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Independent, process-lifetime tenant issuer trust. HTTP callers never supply
/// issuers, credential type or vocabulary to this opt-in verification endpoint.
/// </summary>
internal sealed class HostPinnedVcdm20IssuerRegistry
{
    private static readonly HashSet<string> AllowedPolicyFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "TenantId", "PolicyId", "CredentialType", "SubjectContextUri",
        "TrustedIssuerDids", "DeniedCredentialSha256", "MinimumStatusObservedAtUtc"
    };

    private readonly Dictionary<(Guid Tenant, string PolicyId), HostPinnedVcdm20IssuerPolicy> _policies = [];

    public HostPinnedVcdm20IssuerRegistry(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        IConfigurationSection root = configuration.GetSection("Vcdm20VerifierTrust:Policies");
        if (root.Value is not null)
        {
            throw new InvalidOperationException("Invalid host-owned VC2 trust configuration.");
        }

        IConfigurationSection[] entries = [.. root.GetChildren()];
        if (entries.Length > 128)
        {
            throw new InvalidOperationException("Too many host-owned VC2 issuer trust policies.");
        }

        foreach (IConfigurationSection entry in entries)
        {
            // A typo in a host-only emergency denial or incident cutoff must
            // not silently weaken a verifier policy while the host starts.
            // Scalar fields must also reject nested configuration.
            if (entry.Value is not null)
            {
                throw new InvalidOperationException("Invalid host-owned VC2 trust policy structure.");
            }

            foreach (IConfigurationSection field in entry.GetChildren())
            {
                bool isList = string.Equals(field.Key, "TrustedIssuerDids",
                    StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(field.Key, "DeniedCredentialSha256",
                        StringComparison.OrdinalIgnoreCase);
                if (!AllowedPolicyFields.Contains(field.Key) ||
                    (!isList && field.GetChildren().Any()))
                {
                    throw new InvalidOperationException(
                        "Unknown or nested host-owned VC2 trust policy field.");
                }
            }

            string? tenantText = entry["TenantId"];
            string? policyId = entry["PolicyId"];
            string? type = entry["CredentialType"];
            string? contextText = entry["SubjectContextUri"];
            IConfigurationSection issuerSection = entry.GetSection("TrustedIssuerDids");
            IConfigurationSection[] issuers = [.. issuerSection.GetChildren()];
            IConfigurationSection denialSection = entry.GetSection("DeniedCredentialSha256");
            IConfigurationSection[] denialEntries = [.. denialSection.GetChildren()];
            if (!Guid.TryParse(tenantText, out Guid tenant) || tenant == Guid.Empty ||
                !IsPolicyId(policyId) || !IsCredentialType(type) ||
                !IsContext(contextText, out Uri? context) ||
                issuerSection.Value is not null || issuers.Length is < 1 or > 16 ||
                denialSection.Value is not null || denialEntries.Length > 256)
            {
                throw new InvalidOperationException("Invalid host-owned VC2 issuer trust policy.");
            }

            var unique = new HashSet<string>(StringComparer.Ordinal);
            foreach (IConfigurationSection issuer in issuers)
            {
                string? did = issuer.Value;
                if (did is null || did.Length > 255 || issuer.GetChildren().Any() ||
                    !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _) ||
                    !unique.Add(did))
                {
                    throw new InvalidOperationException("Invalid or duplicate host-owned VC2 issuer DID.");
                }
            }

            // Emergency denial is a protected, verifier-owned operator decision.
            // Reject the entire deployment configuration rather than silently
            // ignoring a malformed, duplicate or oversized original-JWT digest.
            var denied = new HashSet<string>(StringComparer.Ordinal);
            foreach (IConfigurationSection denial in denialEntries)
            {
                string? digest = denial.Value;
                if (digest is not { Length: 64 } ||
                    !digest.All(static character =>
                        character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                    denial.GetChildren().Any() || !denied.Add(digest))
                {
                    throw new InvalidOperationException("Invalid or duplicate host-owned VC2 denial digest.");
                }
            }

            // A host-owned incident boundary must never be supplied by an HTTP
            // caller. Require canonical UTC round-trip format, reject nested
            // configuration, and fail startup instead of ignoring bad policy.
            IConfigurationSection cutoffSection = entry.GetSection("MinimumStatusObservedAtUtc");
            DateTimeOffset? minimumObservedAt = null;
            if (cutoffSection.GetChildren().Any())
            {
                throw new InvalidOperationException("Invalid host-owned VC2 status observation cutoff.");
            }

            if (cutoffSection.Value is string cutoffText)
            {
                if (!DateTimeOffset.TryParseExact(cutoffText, "O",
                        CultureInfo.InvariantCulture, DateTimeStyles.None,
                        out DateTimeOffset parsedCutoff) ||
                    parsedCutoff.Offset != TimeSpan.Zero ||
                    parsedCutoff < DateTimeOffset.UnixEpoch ||
                    !string.Equals(parsedCutoff.ToString("O", CultureInfo.InvariantCulture),
                        cutoffText, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Invalid host-owned VC2 status observation cutoff.");
                }

                minimumObservedAt = parsedCutoff;
            }

            if (!_policies.TryAdd((tenant, policyId!),
                    new HostPinnedVcdm20IssuerPolicy(
                        [.. unique], type!, context!, [.. denied], minimumObservedAt)))
            {
                throw new InvalidOperationException("Duplicate tenant VC2 issuer trust policy.");
            }
        }
    }

    internal bool TryGet(Guid tenant, string policyId, out HostPinnedVcdm20IssuerPolicy? policy) =>
        _policies.TryGetValue((tenant, policyId), out policy);

    internal static bool IsPolicyId(string? value) =>
        value is { Length: > 0 and <= 64 } &&
        value.All(static character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool IsCredentialType(string? value) =>
        value is { Length: > 0 and <= 128 } &&
        !value.Any(char.IsWhiteSpace) &&
        !string.Equals(value, "VerifiableCredential", StringComparison.Ordinal);

    private static bool IsContext(string? value, out Uri? context)
    {
        context = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2_048 ||
            !Uri.TryCreate(value, UriKind.Absolute, out Uri? parsed) ||
            !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            parsed.Host.Length == 0 || parsed.UserInfo.Length != 0 ||
            parsed.Fragment.Length != 0 ||
            !string.Equals(parsed.AbsoluteUri, value, StringComparison.Ordinal))
        {
            return false;
        }

        context = parsed;
        return true;
    }
}

internal sealed record HostPinnedVcdm20IssuerPolicy(
    string[] TrustedIssuerDids, string CredentialType, Uri SubjectContextUri,
    string[] DeniedCredentialSha256, DateTimeOffset? MinimumStatusObservedAtUtc);

/// <summary>
/// A verifier host, not an authenticated caller, chooses current/historical VC2
/// issuer trust and the exact signed credential vocabulary for this operation.
/// The result authenticates an issuer statement only, not holder possession,
/// live revocation, legal identity or business authorization.
/// </summary>
internal static class HostPinnedVcdm20TrustedIssuerVerificationEndpoint
{
    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify-host-pinned", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyHostPinnedVcdm20Issuer")
            .WithSummary("Verify a direct VC2 JWT against a server-owned tenant issuer/type/context policy")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/vcdm20/verify-host-pinned-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyHostPinnedVcdm20IssuerWithStatus")
            .WithSummary("Verify a direct VC2 JWT with host-owned issuer policy and the original issuer's fresh signed status")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult Verify(
        [FromBody] VerifyHostPinnedVcdm20Request request,
        [FromServices] HostPinnedVcdm20IssuerRegistry registry,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!HostPinnedVcdm20IssuerRegistry.IsPolicyId(request.PolicyId) ||
            request.Credential is not { Length: > 0 and <= 65_536 } ||
            request.ExpectedHolderDid is not { Length: > 0 and <= 255 } ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                request.ExpectedHolderDid, out _))
        {
            return Results.Problem(
                title: "Invalid Host-Pinned VC2 Verification Request",
                detail: "A policy identifier, bounded direct VC2 JWT and holder did:key are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.PolicyId!, out HostPinnedVcdm20IssuerPolicy? policy) ||
            policy is null)
        {
            // An unknown/foreign policy never discloses tenant issuer enrollment.
            return Results.Ok(new VerifyVcdm20TrustedIssuersResponse("Invalid", null, null));
        }

        // Verify the original Ed25519 issuer statement before comparing the
        // exact JWT digest. The caller cannot supply or suppress operator denial.
        Vcdm20VerifierPolicyResult status = Vcdm20VerifierDenylist.Check(
            request.Credential, policy.TrustedIssuerDids, policy.DeniedCredentialSha256,
            request.ExpectedHolderDid, policy.CredentialType, policy.SubjectContextUri,
            clock.GetUtcNow(), out string actualIssuer, out var verifiedSubject);
        if (status != Vcdm20VerifierPolicyResult.SignedButStatusUnchecked)
        {
            // Neither an authentic denied credential nor a forged one releases
            // issuer identity or claims. DeniedByVerifier is not issuer revocation.
            string responseStatus = status == Vcdm20VerifierPolicyResult.DeniedByVerifier
                ? "DeniedByVerifier" : "Invalid";
            return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(responseStatus, null, null));
        }

        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
            "SignedButStatusUnchecked", actualIssuer, verifiedSubject));
    }
    /// <summary>
    /// Require the actual issuer's real Ed25519 signed, current HeroSSID status
    /// snapshot in addition to immutable tenant-owned issuer/type/context and
    /// emergency-denial policies. The HTTP caller can supply the status bytes,
    /// but never their signer, local allowlist, or a bypass for operator denial.
    /// A signed non-listing is not a guarantee of complete or live revocation.
    /// </summary>
    internal static IResult VerifyWithStatus(
        [FromBody] VerifyHostPinnedVcdm20WithStatusRequest request,
        [FromServices] HostPinnedVcdm20IssuerRegistry registry,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!HostPinnedVcdm20IssuerRegistry.IsPolicyId(request.PolicyId) ||
            request.Credential is not { Length: > 0 and <= 65_536 } ||
            request.RevocationSnapshot is not { Length: > 0 and <= 65_536 } ||
            request.ExpectedHolderDid is not { Length: > 0 and <= 255 } ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                request.ExpectedHolderDid, out _))
        {
            return Results.Problem(
                title: "Invalid Host-Pinned VC2 Status Verification Request",
                detail: "A policy identifier, bounded direct VC2 JWT, issuer-signed status snapshot and holder did:key are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenant = tenantContext.GetCurrentTenantId();
        if (tenant == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        if (!registry.TryGet(tenant, request.PolicyId!, out HostPinnedVcdm20IssuerPolicy? policy) ||
            policy is null)
        {
            return Results.Ok(new VerifyVcdm20TrustedIssuersResponse("Invalid", null, null));
        }

        Vcdm20VerifierPolicyResult status;
        string actualIssuer;
        System.Text.Json.JsonElement verifiedSubject;
        DateTimeOffset now = clock.GetUtcNow();
        if (policy.MinimumStatusObservedAtUtc is DateTimeOffset cutoff)
        {
            status = Vcdm20VerifierDenylist.CheckWithStatusObservedAfter(
                request.Credential, request.RevocationSnapshot, policy.TrustedIssuerDids,
                policy.DeniedCredentialSha256, request.ExpectedHolderDid,
                policy.CredentialType, policy.SubjectContextUri, now, cutoff,
                out actualIssuer, out verifiedSubject);
        }
        else
        {
            status = Vcdm20VerifierDenylist.CheckWithStatus(
                request.Credential, request.RevocationSnapshot, policy.TrustedIssuerDids,
                policy.DeniedCredentialSha256, request.ExpectedHolderDid,
                policy.CredentialType, policy.SubjectContextUri, now,
                out actualIssuer, out verifiedSubject);
        }
        if (status != Vcdm20VerifierPolicyResult.SignedNotListed)
        {
            string responseStatus = status switch
            {
                Vcdm20VerifierPolicyResult.DeniedByVerifier => "DeniedByVerifier",
                Vcdm20VerifierPolicyResult.IssuerReportedRevoked => "IssuerReportedRevoked",
                _ => "Invalid"
            };
            // All rejection responses withhold issuer and subject, even if
            // the status was signed by a trusted issuer.
            return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(responseStatus, null, null));
        }

        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
            "SignedNotListed", actualIssuer, verifiedSubject));
    }
}

/// <summary>
/// No trusted issuer, credential type, vocabulary or status decision is
/// accepted from the caller; unknown JSON members fail binding.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class VerifyHostPinnedVcdm20Request
{
    public string? PolicyId { get; init; }
    public string? Credential { get; init; }
    public string? ExpectedHolderDid { get; init; }
}


/// <summary>
/// Caller supplies an original VC2 JWT and same-issuer signed status but cannot
/// override any verifier-owned issuer, context, type or emergency-denial policy.
/// This is issuer provenance/status evidence, not holder control or authorization.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class VerifyHostPinnedVcdm20WithStatusRequest
{
    public string? PolicyId { get; init; }
    public string? Credential { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? RevocationSnapshot { get; init; }
}
