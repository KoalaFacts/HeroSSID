using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// A Wallet display preview and the exact signed issuer observation used to prepare it.
/// The Wallet still owns the real full-disclosure UI and informed-consent decision.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebOnlineWalletPreview(
    JwtVcJsonPinnedDidWebWalletEmergencyPreview Disclosure, string SignedStatusJwt);

/// <summary>
/// Opt-in online Wallet preview of a pinned did:web issuer's original VC1.1 JWT.
/// This does not imply live non-revocation, independent Wallet interoperability,
/// consent, real-world identity or business authorization.
/// </summary>
public static class JwtVcJsonPinnedDidWebWalletOnlinePreflight
{
    private const int MaximumOriginalCredentialLength = 65_536;
    private const int MaximumDeniedCredentialDigests = 256;

    /// <summary>
    /// Verify the complete independently approved credential and app-authenticated
    /// request BEFORE a status GET, then verify the signed exact-original status
    /// and Wallet emergency policy BEFORE returning full-disclosure claims.
    /// No holder private key, nonce consumption or consent action occurs here.
    ///
    /// The caller's HttpClient MUST have an independently audited public-only,
    /// credential-free, nonredirecting transport. Prefer the isolated overload.
    /// The application must authenticate the verifier request separately.
    /// </summary>
    public static async Task<JwtVcJsonPinnedDidWebOnlineWalletPreview?> TryPrepareAsync(
        Uri independentlyPinnedStatusUri, HttpClient http,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid,
        IReadOnlyCollection<string> deniedCredentialSha256, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(independentlyPinnedStatusUri);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(authenticatedChallenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(clock);

        // A failed local issuer/holder/request/incident check must never
        // disclose a credential-specific status lookup to a remote server.
        // These are independently configured Wallet pins, not JWT-provided
        // issuer, endpoint or verifier policy.
        DateTimeOffset now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumOriginalCredentialLength ||
            !ValidAuthenticatedRequest(authenticatedChallenge, trustedIssuerDid,
                expectedCredentialType, expectedSubjectContextUri, now) ||
            !IsLocallyAllowed(credentialJwt, deniedCredentialSha256))
        {
            return null;
        }

        // Snapshot the independently enrolled key ONCE across network awaits.
        // No untrusted JWT, status response or DID document may select it.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (!JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                credentialJwt, trustedIssuerDid, trustedVerificationMethodId,
                pinnedKey, expectedIssuerName, expectedCredentialId,
                holderDid, expectedCredentialType, expectedSubjectContextUri,
                now, out _))
        {
            return null;
        }

        JwtVcJsonIssuerStatusFetchResult? fetched =
            await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                independentlyPinnedStatusUri, http, credentialJwt,
                trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
                clock, maximumDuration, cancellationToken).ConfigureAwait(false);
        if (fetched is null || fetched.Status != RevocationSnapshotCheckResult.NotListed)
        {
            return null;
        }

        // Recheck the entire original issuer signature and exact subject,
        // current signed status, app-authenticated request and authoritative
        // Wallet emergency policy after the network await. No claims escape
        // from the earlier pre-network verification.
        if (!JwtVcJsonPinnedDidWebWalletPreflight.TryPrepareWithEmergencyDenylist(
                authenticatedChallenge, credentialJwt, fetched.SignedStatusJwt,
                trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
                expectedIssuerName, expectedCredentialId, expectedCredentialType,
                expectedSubjectContextUri, holderDid, deniedCredentialSha256,
                clock, out JwtVcJsonPinnedDidWebWalletEmergencyPreview? disclosure) ||
            disclosure is null)
        {
            return null;
        }

        return new JwtVcJsonPinnedDidWebOnlineWalletPreview(
            disclosure, fetched.SignedStatusJwt);
    }

    /// <summary>
    /// Secure default: public-address-only HTTPS, no redirects, proxy, cookies,
    /// credentials, trace headers or second DNS lookup. Status URI and pins
    /// still require independent operator approval.
    /// </summary>
    public static async Task<JwtVcJsonPinnedDidWebOnlineWalletPreview?>
        TryPrepareWithIsolatedTransportAsync(
            Uri independentlyPinnedStatusUri,
            PresentationChallenge authenticatedChallenge, string credentialJwt,
            string trustedIssuerDid, string trustedVerificationMethodId,
            byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
            Uri expectedCredentialId, string expectedCredentialType,
            Uri expectedSubjectContextUri, string holderDid,
            IReadOnlyCollection<string> deniedCredentialSha256, TimeProvider clock,
            TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        using var handler =
            JwtVcJsonPinnedDidWebIssuerStatusTransport.CreateIsolatedStatusTransportHandler();
        using var http = new HttpClient(handler);
        return await TryPrepareAsync(independentlyPinnedStatusUri, http,
            authenticatedChallenge, credentialJwt, trustedIssuerDid,
            trustedVerificationMethodId, independentlyPinnedIssuerPublicKey,
            expectedIssuerName, expectedCredentialId, expectedCredentialType,
            expectedSubjectContextUri, holderDid, deniedCredentialSha256,
            clock, maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// AFTER the Wallet application actually displays the full preview and
    /// obtains meaningful informed consent, sign the unchanged original issuer
    /// credential using the holder's own Ed25519 seed. Re-authenticates the
    /// issuer, original credential, status, current Wallet policy, challenge,
    /// displayed subject and holder seed; checks expiry again after signing.
    /// This method cannot attest that real consent was obtained.
    /// </summary>
    public static string CreateAfterPreview(
        JwtVcJsonPinnedDidWebOnlineWalletPreview preview,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        byte[] independentlyPinnedIssuerPublicKey,
        IReadOnlyCollection<string> deniedCredentialSha256,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(authenticatedChallenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);
        if (preview.Disclosure is null)
        {
            throw new ArgumentException(
                "An authenticated Wallet online disclosure preview is required.",
                nameof(preview));
        }

        return JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterEmergencyDenylistPreview(
            preview.Disclosure, authenticatedChallenge, credentialJwt,
            preview.SignedStatusJwt, independentlyPinnedIssuerPublicKey,
            deniedCredentialSha256, holderSeed, clock);
    }

    private static bool IsLocallyAllowed(
        string credentialJwt, IReadOnlyCollection<string> deniedCredentialSha256)
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

        string originalDigest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string? digest in snapshot)
        {
            if (digest is not { Length: 64 } ||
                !digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                !unique.Add(digest) ||
                string.Equals(digest, originalDigest, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ValidAuthenticatedRequest(
        PresentationChallenge challenge, string trustedIssuerDid,
        string expectedCredentialType, Uri expectedContext, DateTimeOffset now) =>
        string.Equals(challenge.TrustedIssuerDid, trustedIssuerDid,
            StringComparison.Ordinal) &&
        PresentationChallengePolicy.IsValidNonce(challenge.Nonce) &&
        !string.IsNullOrWhiteSpace(challenge.Audience) &&
        challenge.Audience.Length <= PresentationChallengePolicy.MaximumIdentifierLength &&
        challenge.ExpiresAt > now &&
        challenge.ExpiresAt <= now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) &&
        (challenge.CredentialType is null) == (challenge.SubjectContextUri is null) &&
        (challenge.CredentialType is null ||
         string.Equals(challenge.CredentialType, expectedCredentialType,
             StringComparison.Ordinal)) &&
        (challenge.SubjectContextUri is null ||
         string.Equals(challenge.SubjectContextUri.AbsoluteUri, expectedContext.AbsoluteUri,
             StringComparison.Ordinal));
}
