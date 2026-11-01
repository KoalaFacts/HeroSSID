using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated non-.NET verifier adapter for independently enrolled active
/// issuers, exact historical VC2 JWT pins, and post-incident signed status.
/// No JWT field automatically grants issuer trust or business authority.
/// </summary>
internal static class Vcdm20RetiredIssuerIncidentHttpEndpoint
{
    private const int MaximumJwtLength = 65_536;
    private const int MaximumActiveIssuers = 16;
    private const int MaximumDistinctIssuers = 16;
    private const int MaximumRetiredPins = 256;

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify-active-and-retired-after-incident",
                VerifyWithStatusAfterCutoff)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20ActiveAndRetiredAfterIncident")
            .WithSummary("Require post-incident genuine issuer status for an active or exact-pinned retired VC2 JWT")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult VerifyWithStatusAfterCutoff(
        [FromBody] VerifyVcdm20RetiredIssuerIncidentRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        if (!TryValidate(request, now, out string[] active,
                out Vcdm20RetiredCredentialPin[] retired))
        {
            return Results.Problem(
                title: "Invalid VC2 Incident Verification Request",
                detail: "Supply an original bounded VC2 JWT, trusted active issuer DIDs or exact historical retired issuer pins, pinned holder/type/HTTPS context, authentic issuer status and a valid verifier-owned observation cutoff.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // The caller, not the JWT or its successor header, independently owns
        // the trust inventory and incident cutoff. The SDK authenticates the
        // ORIGINAL issuer Ed25519 signature, exact retired JWT fingerprint and
        // the actual issuer's short-lived status before disclosing any claims.
        var outcome = Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff(
            request.Credential!, request.RevocationSnapshot!, active, retired,
            request.ExpectedHolderDid!, request.ExpectedCredentialType!,
            request.SubjectContextUri!, now, request.MinimumObservedAt!.Value,
            out string verifiedIssuer, out JsonElement verifiedSubject);

        // A revoked, stale, untrusted or malformed result releases no issuer
        // identity or subject, even if the holder is mentioned in the JWT.
        bool disclose = outcome == Vcdm20VerifierPolicyResult.SignedNotListed;
        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse(
            outcome.ToString(), disclose ? verifiedIssuer : null,
            disclose ? verifiedSubject : (JsonElement?)null));
    }

    private static bool TryValidate(
        VerifyVcdm20RetiredIssuerIncidentRequest request, DateTimeOffset now,
        out string[] active, out Vcdm20RetiredCredentialPin[] retired)
    {
        active = [];
        retired = [];
        if (string.IsNullOrWhiteSpace(request.Credential) ||
            request.Credential.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(request.ExpectedHolderDid) ||
            !ValidDid(request.ExpectedHolderDid) ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.ExpectedCredentialType.Length > 128 ||
            request.ExpectedCredentialType.Any(char.IsWhiteSpace) ||
            request.SubjectContextUri is not { IsAbsoluteUri: true } context ||
            context.Scheme != Uri.UriSchemeHttps ||
            context.Host.Length == 0 ||
            context.UserInfo.Length != 0 || context.Fragment.Length != 0 ||
            context.AbsoluteUri.Length > 2048 ||
            request.MinimumObservedAt is not DateTimeOffset cutoff ||
            cutoff < DateTimeOffset.UnixEpoch || cutoff > now ||
            request.ActiveIssuerDids is null || request.RetiredCredentialPins is null ||
            request.ActiveIssuerDids.Count > MaximumActiveIssuers ||
            request.RetiredCredentialPins.Count > MaximumRetiredPins ||
            request.ActiveIssuerDids.Count == 0 && request.RetiredCredentialPins.Count == 0)
        {
            return false;
        }

        string[] activeSnapshot = request.ActiveIssuerDids.ToArray();
        Vcdm20RetiredCredentialPin[] retiredSnapshot =
            request.RetiredCredentialPins.ToArray();
        if (activeSnapshot.Length != request.ActiveIssuerDids.Count ||
            retiredSnapshot.Length != request.RetiredCredentialPins.Count)
        {
            return false;
        }

        // Reject the ENTIRE policy before credential verification. Duplicate
        // digests, active/retired overlap, malformed late entries and excessive
        // distinct issuer DIDs are errors, never silently ignored exceptions.
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

        var digests = new HashSet<string>(StringComparer.Ordinal);
        foreach (Vcdm20RetiredCredentialPin pin in retiredSnapshot)
        {
            if (pin is null || !ValidDid(pin.IssuerDid) ||
                activeDids.Contains(pin.IssuerDid) ||
                !ValidDigest(pin.CredentialSha256) ||
                !digests.Add(pin.CredentialSha256))
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
        digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

/// <summary>
/// The relying party must independently provision active trust and historical
/// exact-JWT pins before any compromised issuer key is considered retired.
/// A signed observation is neither a full real-time registry nor holder proof.
/// </summary>
public sealed record class VerifyVcdm20RetiredIssuerIncidentRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? ActiveIssuerDids { get; init; }
    public IReadOnlyCollection<Vcdm20RetiredCredentialPin>? RetiredCredentialPins { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
    public DateTimeOffset? MinimumObservedAt { get; init; }
}
