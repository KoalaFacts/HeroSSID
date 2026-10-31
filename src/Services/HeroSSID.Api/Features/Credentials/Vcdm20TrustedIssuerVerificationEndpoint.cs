using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Independent verifier-owned issuer trust for direct VC2 JWTs.</summary>
internal static class Vcdm20TrustedIssuerVerificationEndpoint
{
    private const int MaximumJwtLength = 65_536;
    private const int MaximumTrustedIssuers = 16;

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify-trusted-issuers", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuers")
            .WithSummary("Verify direct VC2 credential against an independently enrolled issuer DID allowlist")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/vcdm20/verify-trusted-issuers-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuersWithStatus")
            .WithSummary("Verify direct VC2 credential and status using its authenticated issuer signer")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
        credentials.MapPost("/vcdm20/verify-trusted-issuers-with-denylist", VerifyWithDenylist)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuersWithDenylist")
            .WithSummary("Apply independently owned emergency SHA-256 JWT denial to authentic direct VC2 credentials")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/vcdm20/verify-trusted-issuers-with-denylist-and-status", VerifyWithDenylistAndStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuersWithDenylistAndStatus")
            .WithSummary("Also require genuine same-issuer status; no clean status overrides local emergency denial")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult VerifyWithDenylist(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyDenylistCore(request, clock, withStatus: false);

    internal static IResult VerifyWithDenylistAndStatus(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock) =>
        VerifyDenylistCore(request, clock, withStatus: true);

    private static IResult VerifyDenylistCore(
        VerifyVcdm20TrustedIssuersRequest request, TimeProvider clock, bool withStatus)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidateDenylistRequest(request, withStatus,
                out string[] issuers, out string[] denied))
        {
            return InvalidRequest();
        }

        // The source JWT, issuer signer, holder, context, type, expiry and
        // any actual issuer's status must validate before returning claims.
        // The SDK distinguishes a verifier-owned local denial from issuer revocation.
        string authenticatedIssuer;
        JsonElement authenticatedSubject;
        DateTimeOffset now = clock.GetUtcNow();
        Vcdm20VerifierPolicyResult status;
        if (withStatus)
        {
            status = Vcdm20VerifierDenylist.CheckWithStatus(
                request.Credential!, request.RevocationSnapshot!, issuers, denied,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, now,
                out authenticatedIssuer, out authenticatedSubject);
        }
        else
        {
            status = Vcdm20VerifierDenylist.Check(
                request.Credential!, issuers, denied, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!, now,
                out authenticatedIssuer, out authenticatedSubject);
        }

        bool disclose = status is Vcdm20VerifierPolicyResult.SignedButStatusUnchecked
            or Vcdm20VerifierPolicyResult.SignedNotListed;
        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
            status.ToString(), disclose ? authenticatedIssuer : null,
            disclose ? authenticatedSubject : (JsonElement?)null));
    }

    private static bool TryValidateDenylistRequest(
        VerifyVcdm20TrustedIssuersRequest request, bool withStatus,
        out string[] issuers, out string[] denied)
    {
        issuers = [];
        denied = [];
        IReadOnlyCollection<string>? supplied = request.DeniedCredentialSha256;
        if (supplied is null || supplied.Count > 256 ||
            !TryValidate(request with { DeniedCredentialSha256 = null },
                withStatus, out issuers))
        {
            return false;
        }

        // Read the entire verifier-owned policy once, and reject even a
        // malformed LATE entry. Never treat an invalid policy as an empty set.
        string[] snapshot = supplied.ToArray();
        if (snapshot.Length != supplied.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in snapshot)
        {
            if (digest is not { Length: 64 } ||
                !digest.All(static character =>
                    character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                !unique.Add(digest))
            {
                return false;
            }
        }

        denied = snapshot;
        return true;
    }

    /// <summary>
    /// Verify original VC2 signer from the caller's separately enrolled trust policy.
    /// This authenticates issuer statements only, not holder control or authorization.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);
        if (!TryValidate(request, withStatus: false, out string[] issuers))
        {
            return InvalidRequest();
        }

        if (!Vcdm20TrustedIssuerVerifier.TryVerify(
                request.Credential!, issuers, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!,
                clock.GetUtcNow(), out string authenticatedIssuer, out var subject))
        {
            return InvalidCredential();
        }

        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
            "SignedButStatusUnchecked", authenticatedIssuer, subject));
    }

    /// <summary>
    /// Check the signed status of the exact credential with ONLY the signer
    /// independently authenticated by the direct VC2 verification. A snapshot
    /// from another still-enrolled issuer can never clear the credential.
    /// </summary>
    internal static IResult VerifyWithStatus(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);
        if (!TryValidate(request, withStatus: true, out string[] issuers))
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (!Vcdm20TrustedIssuerVerifier.TryVerify(
                request.Credential!, issuers, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!,
                now, out string authenticatedIssuer, out var subject))
        {
            return InvalidCredential();
        }

        var status = Vcdm20RevocationSnapshot.Check(
            request.RevocationSnapshot!, request.Credential!, authenticatedIssuer, now);
        return status == Vcdm20RevocationCheckResult.SignedNotListed
            ? Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
                status.ToString(), authenticatedIssuer, subject))
            : Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
                status.ToString(), null, null));
    }

    private static bool TryValidate(
        VerifyVcdm20TrustedIssuersRequest request, bool withStatus,
        out string[] issuers)
    {
        issuers = [];
        string? credential = request.Credential;
        string? expectedHolder = request.ExpectedHolderDid;
        string? expectedType = request.ExpectedCredentialType;
        Uri? context = request.SubjectContextUri;
        IReadOnlyCollection<string>? trusted = request.TrustedIssuerDids;
        string? status = request.RevocationSnapshot;

        // Existing unchecked routes must never silently ignore a submitted
        // caller-owned emergency denial policy, including an empty array.
        if (request.DeniedCredentialSha256 is not null)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(credential) ||
            credential.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(expectedHolder) ||
            expectedHolder.Length > 255 ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolder, out _) ||
            string.IsNullOrWhiteSpace(expectedType) ||
            expectedType.Length > 128 || expectedType.Any(char.IsWhiteSpace) ||
            context is null || !context.IsAbsoluteUri ||
            context.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(context.UserInfo) ||
            !string.IsNullOrEmpty(context.Fragment) ||
            context.AbsoluteUri.Length > 2048)
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
        else if (status is not null)
        {
            // Never silently ignore a status when the caller chose unchecked verification.
            return false;
        }

        if (trusted is null || trusted.Count is < 1 or > MaximumTrustedIssuers)
        {
            return false;
        }

        // Copy once to prevent a mutable caller collection from changing after
        // validation. Never read issuer trust from signed but untrusted claims.
        string[] snapshot = trusted.ToArray();
        if (snapshot.Length != trusted.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string issuerDid in snapshot)
        {
            if (string.IsNullOrWhiteSpace(issuerDid) ||
                issuerDid.Length > 255 ||
                !unique.Add(issuerDid) ||
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
        detail: "Bounded direct VC2 JWT, 1–16 distinct independently trusted issuer DIDs, holder, type and HTTPS vocabulary are required; issuer status and an explicit canonical verifier denylist must be supplied only on their matching dedicated endpoints.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult InvalidCredential() =>
        Results.Ok(new VerifyVcdm20TrustedIssuersResponse("Invalid", null, null));
}

/// <summary>Policy is owned by the verifier; never infer issuer trust from a JWT.</summary>
public sealed record class VerifyVcdm20TrustedIssuersRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? TrustedIssuerDids { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
    public IReadOnlyCollection<string>? DeniedCredentialSha256 { get; init; }
}

/// <summary>A signer/subject is returned only after all requested checks pass.</summary>
public sealed record VerifyVcdm20TrustedIssuersResponse(
    string Status, string? VerifiedIssuerDid, JsonElement? VerifiedSubject);
