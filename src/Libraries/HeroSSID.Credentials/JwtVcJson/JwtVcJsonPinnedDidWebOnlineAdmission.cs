using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// A verifier's single-use holder admission outcome. Claims are undefined on failure.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebOnlineAdmissionResponse(
    JwtVcJsonPinnedDidWebIssuerAdmissionResult Result, JsonElement VerifiedSubject);

/// <summary>
/// Optional verifier flow: retrieve a fresh issuer-signed exact-credential observation
/// from an independently pinned HTTPS endpoint, then apply BOTH verifier-local denial
/// and issuer status to a genuine holder presentation with one atomic challenge.
/// This is not a standards-based status service or live non-revocation proof.
/// </summary>
public static class JwtVcJsonPinnedDidWebOnlineAdmission
{
    private const int MaximumDeniedCredentialDigests = 256;

    /// <summary>
    /// Fetch an issuer-signed status for the exact original JWT supplied by the verifier,
    /// then verify the holder VP and atomically spend its one-use challenge. The caller
    /// must independently enroll the issuer key, status URI, verifier request, full
    /// credential policy, and current local incident denylist. No claims are returned
    /// on failure. A genuine revoked or locally denied holder proof consumes its nonce.
    /// Unavailable/forged network status fails before nonce consumption.
    ///
    /// Injected HttpClient transport must independently disable redirects, proxies,
    /// credentials and private-address access. Prefer CheckWithIsolatedTransportAsync.
    /// </summary>
    public static async Task<JwtVcJsonPinnedDidWebOnlineAdmissionResponse> CheckAsync(
        Uri independentlyPinnedStatusUri, HttpClient http,
        string originalCredentialJwt, string presentationJwt,
        Guid verifierTenantId, string expectedAudience, string expectedNonce,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(independentlyPinnedStatusUri);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(originalCredentialJwt);
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);

        var invalid = new JwtVcJsonPinnedDidWebOnlineAdmissionResponse(
            JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, default);

        // Reject a mismatch between the verifier-selected original JWT and the
        // exact original embedded in the holder's VP BEFORE any network access.
        // This extraction is UNTRUSTED until the composite admission gate later
        // verifies real holder+issuer signatures and the request's audience/nonce.
        if (!JwtVcJsonPinnedDidWebPresentationDenylist.TryGetExactOriginalCredential(
                presentationJwt, out string presentedOriginal) ||
            !string.Equals(presentedOriginal, originalCredentialJwt,
                StringComparison.Ordinal) ||
            !IsValidLocalPolicy(deniedCredentialSha256))
        {
            return invalid;
        }

        // Verify the verifier's full *independently pinned* original issuer
        // metadata and expiry BEFORE contacting the issuer's status endpoint.
        // The JWT's untrusted sub is only a candidate for the issuer-signed
        // holder binding; it cannot choose the issuer DID, method, key, name,
        // credential ID, type or context. Claims must not escape this preflight.
        // The holder proof and atomic nonce consumption remain solely in the
        // final admission gate after the fresh remote status has been checked.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (!StrictJwtReader.TryRead(originalCredentialJwt, "JWT", 65_536,
                out JsonElement originalPayload, trustedVerificationMethodId,
                allowMissingType: true) ||
            !StrictJwtReader.TryGetString(originalPayload, "sub",
                out string claimedHolderDid) ||
            !JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                originalCredentialJwt, trustedIssuerDid, trustedVerificationMethodId,
                pinnedKey, expectedIssuerName, expectedCredentialId,
                claimedHolderDid, expectedCredentialType, expectedSubjectContextUri,
                clock.GetUtcNow(), out _))
        {
            return invalid;
        }

        // This transport verifies the genuine original issuer signature and
        // exact pinned did:web method/key before making a credential-free HTTPS
        // request. It then independently validates the issuer's signed, 60-second,
        // exact-original hash status. A redirect or unavailable status fails closed.
        JwtVcJsonIssuerStatusFetchResult? fetched =
            await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                independentlyPinnedStatusUri, http, originalCredentialJwt,
                trustedIssuerDid, trustedVerificationMethodId,
                pinnedKey, clock,
                maximumDuration, cancellationToken).ConfigureAwait(false);
        if (fetched is null)
        {
            return invalid;
        }

        // Do not call the holder verifier separately: that would consume
        // the challenge twice. This single gate checks BOTH local denial and
        // issuer status after genuine issuer+holder verification and one atomic
        // verifier-owned nonce consumption. Recheck status freshness at this
        // second clock reading, including time spent awaiting the network.
        JwtVcJsonPinnedDidWebIssuerAdmissionResult result =
            JwtVcJsonPinnedDidWebIssuerAdmission.Check(
                presentationJwt, fetched.SignedStatusJwt, verifierTenantId,
                expectedAudience, expectedNonce, trustedIssuerDid,
                trustedVerificationMethodId, pinnedKey,
                expectedIssuerName, expectedCredentialId, expectedCredentialType,
                expectedSubjectContextUri, deniedCredentialSha256,
                challenges, clock, out JsonElement subject);
        return new JwtVcJsonPinnedDidWebOnlineAdmissionResponse(result, subject);
    }

    /// <summary>
    /// Secure transport default: isolated public DNS only, no ambient credentials,
    /// cookies, proxy, redirect or secondary DNS lookup, with TLS checking enabled.
    /// The endpoint and issuer key still require independent operator approval.
    /// </summary>
    public static async Task<JwtVcJsonPinnedDidWebOnlineAdmissionResponse>
        CheckWithIsolatedTransportAsync(
            Uri independentlyPinnedStatusUri, string originalCredentialJwt,
            string presentationJwt, Guid verifierTenantId,
            string expectedAudience, string expectedNonce, string trustedIssuerDid,
            string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
            string expectedIssuerName, Uri expectedCredentialId,
            string expectedCredentialType, Uri expectedSubjectContextUri,
            IReadOnlyCollection<string> deniedCredentialSha256,
            IPresentationChallengeStore challenges, TimeProvider clock,
            TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        using var handler =
            JwtVcJsonPinnedDidWebIssuerStatusTransport.CreateIsolatedStatusTransportHandler();
        using var http = new HttpClient(handler);
        return await CheckAsync(independentlyPinnedStatusUri, http,
            originalCredentialJwt, presentationJwt, verifierTenantId,
            expectedAudience, expectedNonce, trustedIssuerDid,
            trustedVerificationMethodId, independentlyPinnedIssuerPublicKey,
            expectedIssuerName, expectedCredentialId, expectedCredentialType,
            expectedSubjectContextUri, deniedCredentialSha256, challenges,
            clock, maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsValidLocalPolicy(
        IReadOnlyCollection<string> deniedCredentialSha256)
    {
        if (deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return false;
        }

        string[] snapshot = deniedCredentialSha256.ToArray();
        if (snapshot.Length != deniedCredentialSha256.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string? digest in snapshot)
        {
            if (digest is not { Length: 64 } ||
                !digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                !unique.Add(digest))
            {
                return false;
            }
        }

        return true;
    }
}
