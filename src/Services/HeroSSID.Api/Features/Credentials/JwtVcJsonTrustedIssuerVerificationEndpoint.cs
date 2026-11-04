using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.JwtVcJson;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Opt-in VC1.1 jwt_vc_json verification across independently enrolled historical
/// and current Ed25519 did:key issuers. Key succession never grants issuer trust.
/// </summary>
internal static class JwtVcJsonTrustedIssuerVerificationEndpoint
{
    private const int MaximumJwtLength = 65_536;
    private const int MaximumTrustedIssuers = 16;

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuers")
            .WithSummary("Verify original VC1.1 JWT signature against independently enrolled current/historical issuer DIDs")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuersWithStatus")
            .WithSummary("Authenticate the actual VC1.1 signer and a current private revocation snapshot from that same issuer")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers-for-audience", VerifyForAudience)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuersForAudience")
            .WithSummary("Verify recipient-bound VC1.1 JWT against independent historical/current issuer pins")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers-for-audience-with-status", VerifyForAudienceWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuersForAudienceWithStatus")
            .WithSummary("Verify recipient-bound VC1.1 JWT and private status from its actual signer")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    /// <summary>
    /// Only the independently supplied issuer keys are candidates. The signed
    /// JWT's iss/kid cannot enroll a new issuer. No holder-key proof is checked.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidate(request, withStatus: false, out string[] issuers))
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        return TryVerifyOriginalSigner(request, issuers, now,
                out string authenticatedIssuer, out _)
            ? VerifiedResult(request, authenticatedIssuer, now, "SignedButStatusUnchecked")
            : InvalidCredential();
    }

    /// <summary>
    /// An issuer-signed snapshot authenticates only the issuer's own complete
    /// reported revoked set. Even another trusted issuer cannot clear this JWT.
    /// No claims or signer are returned on revoked, forged or stale status.
    /// </summary>
    internal static IResult VerifyWithStatus(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidate(request, withStatus: true, out string[] issuers))
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
            (cutoff < DateTimeOffset.UnixEpoch || cutoff > now))
        {
            return InvalidRequest();
        }

        if (!TryVerifyOriginalSigner(request, issuers, now,
                out string authenticatedIssuer, out _))
        {
            return InvalidCredential();
        }

        // Pin the private 60-second status to the REAL original signer, never
        // to an alternate allowlisted DID or attacker-selected JWT header.
        var status = request.MinimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                request.RevocationSnapshot!, request.Credential!, authenticatedIssuer,
                now, minimum)
            : JwtVcJsonRevocationSnapshot.Check(
                request.RevocationSnapshot!, request.Credential!, authenticatedIssuer, now);
        return status switch
        {
            RevocationSnapshotCheckResult.NotListed =>
                VerifiedResult(request, authenticatedIssuer, now, "SignedNotListed"),
            RevocationSnapshotCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse("Revoked", null, null)),
            _ => InvalidCredential()
        };
    }

    /// <summary>
    /// A caller must explicitly pin its own HTTPS recipient and an issuer trust
    /// list. Neither the JWT's aud nor iss establishes recipient or issuer trust.
    /// Existing no-audience endpoints reject this request field.
    /// </summary>
    internal static IResult VerifyForAudience(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidate(request, withStatus: false, out string[] issuers, requireAudience: true))
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        var outcome = JwtVcJsonTrustedIssuerVerifier.CheckForAudience(
            request.Credential!, issuers, request.ExpectedHolderDid!,
            request.ExpectedCredentialType!, request.SubjectContextUri!,
            request.ExpectedAudience!, now, out string signer, out _);
        return outcome == JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked
            ? VerifiedResult(request, signer, now, "SignedButStatusUnchecked")
            : InvalidCredential();
    }

    /// <summary>
    /// Require genuine recipient-bound issuer signature and original-signer
    /// private status; optional verifier-owned cutoff rejects pre-incident
    /// status. This does not prove status completeness or holder control.
    /// </summary>
    internal static IResult VerifyForAudienceWithStatus(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidate(request, withStatus: true, out string[] issuers, requireAudience: true))
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
            (cutoff < DateTimeOffset.UnixEpoch || cutoff > now))
        {
            return InvalidRequest();
        }

        string signer;
        var result = request.MinimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonTrustedIssuerVerifier.CheckForAudienceWithStatusAfterObservationCutoff(
                request.Credential!, request.RevocationSnapshot!, issuers,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, request.ExpectedAudience!, now, minimum,
                out signer, out _)
            : JwtVcJsonTrustedIssuerVerifier.CheckForAudienceWithStatus(
                request.Credential!, request.RevocationSnapshot!, issuers,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, request.ExpectedAudience!, now,
                out signer, out _);
        return result switch
        {
            JwtVcJsonTrustedIssuerCheckResult.SignedNotListed =>
                VerifiedResult(request, signer, now, "SignedNotListed"),
            JwtVcJsonTrustedIssuerCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse("Revoked", null, null)),
            _ => InvalidCredential()
        };
    }

    /// <summary>
    /// Disclose the actual original signer's signed metadata only after the
    /// verifier-owned trust/recipient and optional status gates succeeded.
    /// Revalidate with the authenticated DID and same clock; never trust
    /// JWT-provided issuer or recipient names as policy. Fail closed on drift.
    /// </summary>
    private static IResult VerifiedResult(
        VerifyJwtVcJsonTrustedIssuersRequest request, string signer,
        DateTimeOffset now, string status)
    {
        JsonElement subject;
        string? credentialId;
        string? issuerName;
        DateTimeOffset? notBefore;
        DateTimeOffset? expiresAt;

        bool verified;
        if (request.ExpectedAudience is Uri audience)
        {
            verified = JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
                request.Credential!, signer, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!,
                audience, now, out subject, out credentialId,
                out issuerName, out notBefore, out expiresAt);
        }
        else
        {
            verified = JwtVcJsonCredential.TryVerifyWithValidity(
                request.Credential!, signer, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!,
                now, out subject, out credentialId,
                out issuerName, out notBefore, out expiresAt);
        }

        return verified
            ? Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse(
                status, signer, subject, credentialId, issuerName,
                notBefore, expiresAt))
            : InvalidCredential();
    }

    private static bool TryVerifyOriginalSigner(
        VerifyJwtVcJsonTrustedIssuersRequest request, string[] issuers,
        DateTimeOffset now, out string authenticatedIssuer, out JsonElement subject)
    {
        authenticatedIssuer = string.Empty;
        subject = default;

        // Run the full existing strict VC1.1 JWT verifier for each independently
        // enrolled issuer (at most 16). It checks genuine Ed25519, exact kid,
        // iss/sub, vc.@context, vc.type, subject ID and signed validity bounds.
        foreach (string issuerDid in issuers)
        {
            if (JwtVcJsonCredential.TryVerify(
                    request.Credential!, issuerDid, request.ExpectedHolderDid!,
                    request.ExpectedCredentialType!, request.SubjectContextUri!,
                    now, out subject))
            {
                authenticatedIssuer = issuerDid;
                return true;
            }
        }

        subject = default;
        return false;
    }

    private static bool TryValidate(
        VerifyJwtVcJsonTrustedIssuersRequest request, bool withStatus,
        out string[] issuers, bool requireAudience = false)
    {
        issuers = [];
        string? credential = request.Credential;
        string? holder = request.ExpectedHolderDid;
        string? type = request.ExpectedCredentialType;
        Uri? context = request.SubjectContextUri;
        Uri? audience = request.ExpectedAudience;
        string? status = request.RevocationSnapshot;
        IReadOnlyCollection<string>? trusted = request.TrustedIssuerDids;

        if (string.IsNullOrWhiteSpace(credential) ||
            credential.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(holder) || holder.Length > 255 ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holder, out _) ||
            string.IsNullOrWhiteSpace(type) || type.Length > 128 ||
            type.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(type, UriKind.Absolute, out var typeUri) ||
            typeUri.Scheme != Uri.UriSchemeHttps ||
            typeUri.Host.Length == 0 || typeUri.UserInfo.Length != 0 ||
            context is null || !context.IsAbsoluteUri ||
            context.Scheme != Uri.UriSchemeHttps || context.Host.Length == 0 ||
            context.UserInfo.Length != 0 || context.Fragment.Length != 0 ||
            context.AbsoluteUri.Length > 2048 ||
            (requireAudience &&
                (audience is null || !audience.IsAbsoluteUri ||
                 audience.Scheme != Uri.UriSchemeHttps || audience.Host.Length == 0 ||
                 audience.UserInfo.Length != 0 || audience.Fragment.Length != 0 ||
                 audience.AbsoluteUri.Length > 2048)) ||
            (!requireAudience && audience is not null))
        {
            return false;
        }

        if (withStatus)
        {
            if (string.IsNullOrWhiteSpace(status) || status.Length > MaximumJwtLength)
            {
                return false;
            }
        }
        else if (status is not null || request.MinimumStatusObservedAt is not null)
        {
            // A caller cannot silently pass a status and get an unchecked
            // result merely by choosing the non-status endpoint.
            return false;
        }

        if (trusted is null || trusted.Count is < 1 or > MaximumTrustedIssuers)
        {
            return false;
        }

        // Snapshot caller-owned collections once and reject duplicates. Never
        // discover key trust from untrusted original JWT or issuer status.
        string[] snapshot = trusted.ToArray();
        if (snapshot.Length != trusted.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string issuerDid in snapshot)
        {
            if (string.IsNullOrWhiteSpace(issuerDid) ||
                issuerDid.Length > 255 || !unique.Add(issuerDid) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _))
            {
                return false;
            }
        }

        issuers = snapshot;
        return true;
    }

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Request",
        detail: "A bounded VC1.1 JWT, 1–16 distinct independently pinned Ed25519 issuer DIDs, holder, HTTPS credential type and subject context are required. Status must be present only for the status-verifying endpoint.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult InvalidCredential() =>
        Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse("Invalid", null, null));
}

/// <summary>The caller's independently enrolled issuer keys, not untrusted JWT claims.</summary>
public sealed record class VerifyJwtVcJsonTrustedIssuersRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? TrustedIssuerDids { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public Uri? ExpectedAudience { get; init; }
    public string? RevocationSnapshot { get; init; }

    /// <summary>Verifier-owned optional signed-status observation lower bound, UTC instant.</summary>
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

/// <summary>
/// Disclose signed metadata only after all verifier-owned gates succeed.
/// Descriptive issuer names do not certify legal identity or authority.
/// </summary>
public sealed record VerifyJwtVcJsonTrustedIssuersResponse(
    string Status, string? VerifiedIssuerDid, JsonElement? VerifiedSubject,
    string? VerifiedCredentialId = null, string? VerifiedIssuerName = null,
    DateTimeOffset? VerifiedNotBefore = null, DateTimeOffset? VerifiedExpiresAt = null);
