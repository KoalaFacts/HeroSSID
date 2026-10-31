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

        return TryVerifyOriginalSigner(request, issuers, clock.GetUtcNow(),
                out string authenticatedIssuer, out var subject)
            ? Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse(
                "SignedButStatusUnchecked", authenticatedIssuer, subject))
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
        if (!TryVerifyOriginalSigner(request, issuers, now,
                out string authenticatedIssuer, out var subject))
        {
            return InvalidCredential();
        }

        // Pin the private 60-second status to the REAL original signer, never
        // to an alternate allowlisted DID or attacker-selected JWT header.
        var status = JwtVcJsonRevocationSnapshot.Check(
            request.RevocationSnapshot!, request.Credential!, authenticatedIssuer, now);
        return status switch
        {
            RevocationSnapshotCheckResult.NotListed =>
                Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse(
                    "SignedNotListed", authenticatedIssuer, subject)),
            RevocationSnapshotCheckResult.Revoked =>
                Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse("Revoked", null, null)),
            _ => InvalidCredential()
        };
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
        out string[] issuers)
    {
        issuers = [];
        string? credential = request.Credential;
        string? holder = request.ExpectedHolderDid;
        string? type = request.ExpectedCredentialType;
        Uri? context = request.SubjectContextUri;
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
    public string? RevocationSnapshot { get; init; }
}

/// <summary>Neither signer nor subject can be disclosed on a rejected JWT/status.</summary>
public sealed record VerifyJwtVcJsonTrustedIssuersResponse(
    string Status, string? VerifiedIssuerDid, JsonElement? VerifiedSubject);
