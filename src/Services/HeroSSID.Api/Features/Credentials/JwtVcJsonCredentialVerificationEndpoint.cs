using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated HTTP adapter for issuer-signed W3C VC1.1 jwt_vc_json.
/// The caller supplies independent verifier trust policy. No assertion here
/// proves holder private-key control, identity or business authorization.
/// </summary>
internal static class JwtVcJsonCredentialVerificationEndpoint
{
    private const int MaximumJwtLength = 65_536;

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonCredential")
            .WithSummary("Verify VC1.1 jwt_vc_json issuer signature against caller-pinned policy")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/jwt-vc-json/verify-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonCredentialWithStatus")
            .WithSummary("Verify VC1.1 issuer signature and a separate issuer-signed private revocation snapshot")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
        credentials.MapPost("/jwt-vc-json/verify-for-audience", VerifyForAudience)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonCredentialForAudience")
            .WithSummary("Verify original VC1.1 JWT for independently pinned HTTPS recipient")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        credentials.MapPost("/jwt-vc-json/verify-for-audience-with-status", VerifyForAudienceWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonCredentialForAudienceWithStatus")
            .WithSummary("Verify recipient-pinned VC1.1 JWT and genuine original-issuer status")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        credentials.MapPost("/jwt-vc-json/verify-pinned-issuer-name-and-id", VerifyPinnedIssuerNameAndId)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonPinnedIssuerNameAndId")
            .WithSummary("Verify VC1.1 issuer signature AND independent exact issuer-name and signed-ID pins")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        credentials.MapPost("/jwt-vc-json/verify-pinned-issuer-name-and-id-with-status", VerifyPinnedIssuerNameAndIdWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonPinnedIssuerNameAndIdWithStatus")
            .WithSummary("Authenticate independently pinned VC1.1 issuer metadata and same-issuer signed private status")
            .Produces<VerifyJwtVcJsonCredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);
    }

    /// <summary>
    /// An issuer signature authenticates a statement only; it neither proves
    /// holder private-key control nor checks status. Never infer issuer trust
    /// from the JWT's untrusted iss or from an issuer-signed context itself.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyJwtVcJsonCredentialRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (request.MinimumStatusObservedAt is not null ||
            request.ExpectedAudience is not null ||
            request.ExpectedIssuerName is not null ||
            request.ExpectedCredentialId is not null ||
            request.RevocationSnapshot is not null ||
            !IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri))
        {
            return InvalidRequest(false);
        }

        bool valid = JwtVcJsonCredential.TryVerifyWithValidity(request.Credential!,
            request.TrustedIssuerDid!, request.ExpectedHolderDid!,
            request.ExpectedCredentialType!, request.SubjectContextUri!,
            clock.GetUtcNow(), out var subject, out string? credentialId,
            out string? issuerName, out DateTimeOffset? validFrom,
            out DateTimeOffset? validUntil);
        return Results.Ok(valid
            ? new VerifyJwtVcJsonCredentialResponse(
                "SignedButStatusUnchecked", subject, credentialId, issuerName,
                validFrom, validUntil)
            : new VerifyJwtVcJsonCredentialResponse("Invalid", null));
    }

    /// <summary>
    /// Verify the original issuer-signed VC1.1 statement BEFORE authenticating
    /// a separately signed private issuer status snapshot for the exact token.
    /// SignedNotListed depends on the issuer's complete authoritative revocation
    /// set; this is neither live non-revocation nor holder control.
    /// </summary>
    internal static IResult VerifyWithStatus(
        [FromBody] VerifyJwtVcJsonCredentialWithStatusRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        if (request.ExpectedAudience is not null ||
            request.ExpectedIssuerName is not null ||
            request.ExpectedCredentialId is not null ||
            !IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri) ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumJwtLength ||
            (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
                (cutoff < DateTimeOffset.UnixEpoch || cutoff > now)))
        {
            return InvalidRequest(true);
        }

        if (!JwtVcJsonCredential.TryVerifyWithValidity(request.Credential!,
            request.TrustedIssuerDid!, request.ExpectedHolderDid!,
            request.ExpectedCredentialType!, request.SubjectContextUri!,
            now, out var subject, out string? credentialId, out string? issuerName,
            out DateTimeOffset? validFrom, out DateTimeOffset? validUntil))
        {
            return Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null));
        }

        // The snapshot cannot select its own trust anchor. Its issuer must be
        // the SAME independently pinned DID as the original signed credential.
        var status = request.MinimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                request.RevocationSnapshot!, request.Credential!,
                request.TrustedIssuerDid!, now, minimum)
            : JwtVcJsonRevocationSnapshot.Check(request.RevocationSnapshot!,
                request.Credential!, request.TrustedIssuerDid!, now);
        return status switch
        {
            RevocationSnapshotCheckResult.NotListed =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse(
                    "SignedNotListed", subject, credentialId, issuerName,
                    validFrom, validUntil)),
            RevocationSnapshotCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse("Revoked", null)),
            _ => Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null))
        };
    }

    /// <summary>
    /// Non-.NET verifiers explicitly pin both the exact issuer-signed name
    /// and original signed JWT jti. A real signature with the wrong policy
    /// never releases subject claims. Neither signed assertion is legal identity
    /// or evidence of holder-key possession, consent or business authority.
    /// </summary>
    internal static IResult VerifyPinnedIssuerNameAndId(
        [FromBody] VerifyJwtVcJsonPinnedIssuerNameAndIdRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyPinnedIssuerNameAndIdCore(request, clock, withStatus: false);

    internal static IResult VerifyPinnedIssuerNameAndIdWithStatus(
        [FromBody] VerifyJwtVcJsonPinnedIssuerNameAndIdRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyPinnedIssuerNameAndIdCore(request, clock, withStatus: true);

    private static IResult VerifyPinnedIssuerNameAndIdCore(
        VerifyJwtVcJsonPinnedIssuerNameAndIdRequest request,
        TimeProvider clock, bool withStatus)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        Uri? expectedId = request.ExpectedCredentialId;
        if (!IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri) ||
            !IsValidPinnedMetadataPolicy(request.ExpectedIssuerName, expectedId) ||
            request.ExpectedAudience is not null ||
            (!withStatus && (request.RevocationSnapshot is not null ||
                request.MinimumStatusObservedAt is not null)) ||
            (withStatus && (string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
                request.RevocationSnapshot.Length > MaximumJwtLength ||
                (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
                    (cutoff < DateTimeOffset.UnixEpoch || cutoff > now)))))
        {
            return InvalidRequest(withStatus);
        }

        // Authenticate the original Ed25519 JWT once at the verifier's clock.
        // Compare both independently supplied metadata pins BEFORE returning
        // any of its otherwise genuinely signed subject/ID/name/time fields.
        if (!JwtVcJsonCredential.TryVerifyWithValidity(
                request.Credential!, request.TrustedIssuerDid!,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, now, out JsonElement subject,
                out string? signedId, out string? signedName,
                out DateTimeOffset? validFrom, out DateTimeOffset? validUntil) ||
            !string.Equals(signedName, request.ExpectedIssuerName,
                StringComparison.Ordinal) ||
            !string.Equals(signedId, expectedId!.AbsoluteUri,
                StringComparison.Ordinal))
        {
            return Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null));
        }

        if (!withStatus)
        {
            return Results.Ok(new VerifyJwtVcJsonCredentialResponse(
                "SignedButStatusUnchecked", subject, signedId, signedName,
                validFrom, validUntil));
        }

        // A status JWT cannot introduce a new trust anchor. Its real issuer
        // signature must match the original already independently pinned DID.
        var status = request.MinimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                request.RevocationSnapshot!, request.Credential!,
                request.TrustedIssuerDid!, now, minimum)
            : JwtVcJsonRevocationSnapshot.Check(
                request.RevocationSnapshot!, request.Credential!,
                request.TrustedIssuerDid!, now);
        return status switch
        {
            RevocationSnapshotCheckResult.NotListed =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse(
                    "SignedNotListed", subject, signedId, signedName,
                    validFrom, validUntil)),
            RevocationSnapshotCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse("Revoked", null)),
            _ => Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null))
        };
    }

    private static bool IsValidPinnedMetadataPolicy(string? name, Uri? credentialId) =>
        name is { Length: <= 128 } &&
        !string.IsNullOrWhiteSpace(name) &&
        !name.Any(char.IsControl) &&
        credentialId is { IsAbsoluteUri: true } &&
        credentialId.Scheme == Uri.UriSchemeHttps &&
        !string.IsNullOrWhiteSpace(credentialId.Host) &&
        credentialId.UserInfo.Length == 0 &&
        credentialId.AbsoluteUri.Length <= 2048;

    /// <summary>
    /// Only this explicit adapter accepts an expected HTTPS audience.
    /// Independent issuer/holder/type/context/recipient pins are mandatory.
    /// Genuine signer status is checked on the exact JWT after verification;
    /// none of these checks prove live non-revocation or holder consent.
    /// </summary>
    internal static IResult VerifyForAudience(
        [FromBody] VerifyJwtVcJsonForAudienceRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyForAudienceCore(request, clock, withStatus: false);

    internal static IResult VerifyForAudienceWithStatus(
        [FromBody] VerifyJwtVcJsonForAudienceRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyForAudienceCore(request, clock, withStatus: true);

    private static IResult VerifyForAudienceCore(
        VerifyJwtVcJsonForAudienceRequest request, TimeProvider clock, bool withStatus)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);
        DateTimeOffset now = clock.GetUtcNow();
        Uri? audience = request.ExpectedAudience;
        if (request.ExpectedIssuerName is not null ||
            request.ExpectedCredentialId is not null ||
            !IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri) ||
            audience is not { IsAbsoluteUri: true } ||
            audience.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(audience.Host) ||
            audience.UserInfo.Length != 0 ||
            audience.Fragment.Length != 0 ||
            audience.AbsoluteUri.Length > 2048 ||
            (!withStatus && (request.RevocationSnapshot is not null ||
                request.MinimumStatusObservedAt is not null)) ||
            (withStatus && (string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
                request.RevocationSnapshot.Length > MaximumJwtLength ||
                (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
                    (cutoff < DateTimeOffset.UnixEpoch || cutoff > now)))))
        {
            return Results.Problem(title: "Invalid Request",
                detail: "Independently pinned issuer, holder, HTTPS type, context and recipient are required; status belongs only to the status route.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (!JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
                request.Credential!, request.TrustedIssuerDid!,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, audience, now, out var subject,
                out string? credentialId, out string? issuerName,
                out DateTimeOffset? validFrom, out DateTimeOffset? validUntil))
        {
            return Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null));
        }

        if (!withStatus)
        {
            return Results.Ok(new VerifyJwtVcJsonCredentialResponse(
                "SignedButStatusUnchecked", subject, credentialId, issuerName,
                validFrom, validUntil));
        }

        var status = request.MinimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                request.RevocationSnapshot!, request.Credential!,
                request.TrustedIssuerDid!, now, minimum)
            : JwtVcJsonRevocationSnapshot.Check(
                request.RevocationSnapshot!, request.Credential!,
                request.TrustedIssuerDid!, now);
        return status switch
        {
            RevocationSnapshotCheckResult.NotListed =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse(
                    "SignedNotListed", subject, credentialId, issuerName,
                    validFrom, validUntil)),
            RevocationSnapshotCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonCredentialResponse("Revoked", null)),
            _ => Results.Ok(new VerifyJwtVcJsonCredentialResponse("Invalid", null))
        };
    }

    private static bool IsValidPolicy(string? credential, string? trustedIssuerDid,
        string? holderDid, string? type, Uri? context) =>
        !string.IsNullOrWhiteSpace(credential) &&
        credential.Length <= MaximumJwtLength &&
        !string.IsNullOrWhiteSpace(trustedIssuerDid) &&
        trustedIssuerDid.Length <= 255 &&
        trustedIssuerDid.StartsWith("did:key:", StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(holderDid) &&
        holderDid.Length <= 255 &&
        holderDid.StartsWith("did:key:", StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(type) &&
        type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        Uri.TryCreate(type, UriKind.Absolute, out var typeIri) &&
        typeIri.Scheme == Uri.UriSchemeHttps &&
        typeIri.Host.Length > 0 &&
        typeIri.UserInfo.Length == 0 &&
        context is { IsAbsoluteUri: true } &&
        context.Scheme == Uri.UriSchemeHttps &&
        context.Host.Length > 0 &&
        context.UserInfo.Length == 0 &&
        context.Fragment.Length == 0 &&
        context.AbsoluteUri.Length <= 2048;

    private static IResult InvalidRequest(bool requiresStatus) => Results.Problem(
        title: "Invalid Request",
        detail: requiresStatus
            ? "A bounded VC1.1 JWT, issuer-signed status snapshot, and independently pinned did:key issuer, holder, HTTPS credential type and vocabulary are required."
            : "A bounded VC1.1 JWT and independently pinned did:key issuer, holder, HTTPS credential type and vocabulary are required.",
        statusCode: StatusCodes.Status400BadRequest);
}

/// <summary>Untrusted input; all issuer/holder/type/context values must come from caller policy.</summary>
public sealed class VerifyJwtVcJsonCredentialRequest
{
    public string? Credential { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    /// <summary>Independently pinned metadata belongs only to the opt-in route.</summary>
    public string? ExpectedIssuerName { get; init; }
    public Uri? ExpectedCredentialId { get; init; }
    /// <summary>Unchecked verification must not silently ignore a status JWT.</summary>
    public string? RevocationSnapshot { get; init; }
    /// <summary>Do not silently ignore explicit recipient policy on legacy routes.</summary>
    public Uri? ExpectedAudience { get; init; }
    /// <summary>Reserved for status routes; unchecked verification must reject it.</summary>
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

/// <summary>Separate issuer-signed snapshot is required; this is not a W3C status list.</summary>
public sealed class VerifyJwtVcJsonCredentialWithStatusRequest
{
    public string? Credential { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? ExpectedIssuerName { get; init; }
    public Uri? ExpectedCredentialId { get; init; }
    /// <summary>Do not silently ignore explicit recipient policy on legacy routes.</summary>
    public Uri? ExpectedAudience { get; init; }
    public string? RevocationSnapshot { get; init; }
    /// <summary>Opt-in earliest acceptable issuer status observation time.</summary>
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

/// <summary>
/// A relying party supplies all pins from its own policy, not the JWT.
/// Status belongs only to the explicitly named status route.
/// </summary>
public sealed class VerifyJwtVcJsonForAudienceRequest
{
    public string? Credential { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? ExpectedIssuerName { get; init; }
    public Uri? ExpectedCredentialId { get; init; }
    public Uri? ExpectedAudience { get; init; }
    public string? RevocationSnapshot { get; init; }
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

/// <summary>
 /// All verified subject, ID, issuer-name and original signed temporal
 /// outputs are null on rejection/revocation. Times bound downstream caches,
 /// but do not prove holder control, live status or authorization.
 /// </summary>
/// <summary>
/// Strict opt-in non-.NET verifier policy. Every pin comes from the relying
/// party's own trust policy, not from the untrusted credential. Only the
/// separate status route accepts a private signed revocation snapshot.
/// </summary>
public sealed class VerifyJwtVcJsonPinnedIssuerNameAndIdRequest
{
    public string? Credential { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? ExpectedIssuerName { get; init; }
    public Uri? ExpectedCredentialId { get; init; }
    /// <summary>Must be null: this profile does not authenticate JWT aud.</summary>
    public Uri? ExpectedAudience { get; init; }
    public string? RevocationSnapshot { get; init; }
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

public sealed record VerifyJwtVcJsonCredentialResponse(
    string Status, JsonElement? VerifiedSubject, string? VerifiedCredentialId = null,
    string? VerifiedIssuerName = null,
    DateTimeOffset? VerifiedNotBefore = null,
    DateTimeOffset? VerifiedExpiresAt = null);
