using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.JwtVcJson;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated HTTP adapter for verifier-owned active Ed25519 issuer trust
/// and exact original JWT pins from retired issuers. Neither the submitted
/// JWT nor an issuer successor statement enrolls a trusted signing key.
/// </summary>
internal static class JwtVcJsonRetiredIssuerVerificationEndpoint
{
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumActiveIssuers = 16;
    private const int MaximumDistinctIssuers = 16;
    private const int MaximumRetiredPins = 256;

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/verify-active-and-retired", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonActiveAndRetired")
            .WithSummary("Verify an active issuer or an exact pre-enrolled VC1.1 JWT from a retired issuer")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        credentials.MapPost("/jwt-vc-json/verify-active-and-retired-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonActiveAndRetiredWithStatus")
            .WithSummary("Also require a fresh signed private revocation snapshot from the genuine VC1.1 issuer")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult Verify(
        [FromBody] VerifyJwtVcJsonActiveAndRetiredRequest request,
        [FromServices] TimeProvider clock) => VerifyCore(request, clock, withStatus: false);

    internal static IResult VerifyWithStatus(
        [FromBody] VerifyJwtVcJsonActiveAndRetiredRequest request,
        [FromServices] TimeProvider clock) => VerifyCore(request, clock, withStatus: true);

    private static IResult VerifyCore(
        VerifyJwtVcJsonActiveAndRetiredRequest request, TimeProvider clock, bool withStatus)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        if (!TryValidate(request, withStatus, out string[] active,
                out JwtVcJsonRetiredCredentialPin[] retired))
        {
            return Results.Problem(
                title: "Invalid Request",
                detail: "Supply a bounded original VC1.1 JWT, explicit active issuer DIDs and retired exact-JWT pins, independent holder/HTTPS type/context policy, and status only for the status-checking route. Active and retired issuer policies must be disjoint.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // The SDK authenticates the actual Ed25519 signer, original exact-JWT
        // pin (when retired), holder, type, context, validity and optional
        // same-issuer signed status. The HTTP boundary cannot promote a signer.
        string verifiedIssuer;
        JsonElement verifiedSubject;
        var result = withStatus
            ? JwtVcJsonRetiredIssuerVerifier.CheckWithStatus(
                request.Credential!, request.RevocationSnapshot!, active, retired,
                request.ExpectedHolderDid!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, clock.GetUtcNow(),
                out verifiedIssuer, out verifiedSubject)
            : JwtVcJsonRetiredIssuerVerifier.Check(
                request.Credential!, active, retired, request.ExpectedHolderDid!,
                request.ExpectedCredentialType!, request.SubjectContextUri!,
                clock.GetUtcNow(), out verifiedIssuer, out verifiedSubject);

        if (result is JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked or
            JwtVcJsonTrustedIssuerCheckResult.SignedNotListed)
        {
            return Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse(
                result.ToString(), verifiedIssuer, verifiedSubject));
        }

        // Invalid and Revoked never disclose even the authenticated signer.
        return Results.Ok(new VerifyJwtVcJsonTrustedIssuersResponse(
            result.ToString(), null, null));
    }

    private static bool TryValidate(
        VerifyJwtVcJsonActiveAndRetiredRequest request, bool withStatus,
        out string[] active, out JwtVcJsonRetiredCredentialPin[] retired)
    {
        active = [];
        retired = [];

        if (string.IsNullOrWhiteSpace(request.Credential) ||
            request.Credential.Length > MaximumCredentialLength ||
            string.IsNullOrWhiteSpace(request.ExpectedHolderDid) ||
            request.ExpectedHolderDid.Length > 255 ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                request.ExpectedHolderDid, out _) ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.ExpectedCredentialType.Length > 128 ||
            request.ExpectedCredentialType.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(request.ExpectedCredentialType, UriKind.Absolute, out Uri? typeUri) ||
            typeUri.Scheme != Uri.UriSchemeHttps || typeUri.Host.Length == 0 ||
            typeUri.UserInfo.Length != 0 ||
            request.SubjectContextUri is not { IsAbsoluteUri: true } context ||
            context.Scheme != Uri.UriSchemeHttps || context.Host.Length == 0 ||
            context.UserInfo.Length != 0 || context.Fragment.Length != 0 ||
            context.AbsoluteUri.Length > 2048 ||
            request.ActiveIssuerDids is null ||
            request.RetiredCredentialPins is null ||
            request.ActiveIssuerDids.Count > MaximumActiveIssuers ||
            request.RetiredCredentialPins.Count > MaximumRetiredPins ||
            request.ActiveIssuerDids.Count == 0 && request.RetiredCredentialPins.Count == 0)
        {
            return false;
        }

        if (withStatus)
        {
            if (string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
                request.RevocationSnapshot.Length > MaximumCredentialLength)
            {
                return false;
            }
        }
        else if (request.RevocationSnapshot is not null)
        {
            // Reject silent downgrade when the caller supplied a snapshot but
            // accidentally called the unchecked endpoint.
            return false;
        }

        string[] activeSnapshot = request.ActiveIssuerDids.ToArray();
        JwtVcJsonRetiredCredentialPin[] retiredSnapshot =
            request.RetiredCredentialPins.ToArray();
        if (activeSnapshot.Length != request.ActiveIssuerDids.Count ||
            retiredSnapshot.Length != request.RetiredCredentialPins.Count)
        {
            return false;
        }

        var activeDids = new HashSet<string>(StringComparer.Ordinal);
        var allDids = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in activeSnapshot)
        {
            if (!ValidDid(did) || !activeDids.Add(did))
            {
                return false;
            }

            allDids.Add(did);
        }

        var registeredDigests = new HashSet<string>(StringComparer.Ordinal);
        foreach (JwtVcJsonRetiredCredentialPin pin in retiredSnapshot)
        {
            if (pin is null || !ValidDid(pin.IssuerDid) ||
                activeDids.Contains(pin.IssuerDid) ||
                !ValidDigest(pin.CredentialSha256) ||
                !registeredDigests.Add(pin.CredentialSha256))
            {
                return false;
            }

            allDids.Add(pin.IssuerDid);
        }

        if (allDids.Count > MaximumDistinctIssuers)
        {
            return false;
        }

        active = activeSnapshot;
        retired = retiredSnapshot;
        return true;
    }

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= 255 &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _);

    private static bool ValidDigest(string? digest) =>
        digest is { Length: 64 } &&
        digest.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

/// <summary>
/// Caller-owned trust policy. A pin must originate from a separate trusted
/// issuance inventory, NEVER from blindly accepting a wallet-provided JWT.
/// Neither signature nor a private status snapshot establishes holder control,
/// human identity/consent or business authorization.
/// </summary>
public sealed record class VerifyJwtVcJsonActiveAndRetiredRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? ActiveIssuerDids { get; init; }
    public IReadOnlyCollection<JwtVcJsonRetiredCredentialPin>? RetiredCredentialPins { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
}
