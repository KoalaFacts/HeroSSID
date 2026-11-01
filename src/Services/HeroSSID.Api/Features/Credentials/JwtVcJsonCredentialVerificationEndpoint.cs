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
            !IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri))
        {
            return InvalidRequest(false);
        }

        bool valid = JwtVcJsonCredential.TryVerify(request.Credential!,
            request.TrustedIssuerDid!, request.ExpectedHolderDid!,
            request.ExpectedCredentialType!, request.SubjectContextUri!,
            clock.GetUtcNow(), out var subject);
        return Results.Ok(valid
            ? new VerifyJwtVcJsonCredentialResponse("SignedButStatusUnchecked", subject)
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
        if (!IsValidPolicy(request.Credential, request.TrustedIssuerDid,
                request.ExpectedHolderDid, request.ExpectedCredentialType,
                request.SubjectContextUri) ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumJwtLength ||
            (request.MinimumStatusObservedAt is DateTimeOffset cutoff &&
                (cutoff < DateTimeOffset.UnixEpoch || cutoff > now)))
        {
            return InvalidRequest(true);
        }

        if (!JwtVcJsonCredential.TryVerify(request.Credential!,
            request.TrustedIssuerDid!, request.ExpectedHolderDid!,
            request.ExpectedCredentialType!, request.SubjectContextUri!,
            now, out var subject))
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
                Results.Ok(new VerifyJwtVcJsonCredentialResponse("SignedNotListed", subject)),
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
    public string? RevocationSnapshot { get; init; }
    /// <summary>Opt-in earliest acceptable issuer status observation time.</summary>
    public DateTimeOffset? MinimumStatusObservedAt { get; init; }
}

/// <summary>VerifiedSubject is null whenever validation or status fails.</summary>
public sealed record VerifyJwtVcJsonCredentialResponse(string Status, JsonElement? VerifiedSubject);
