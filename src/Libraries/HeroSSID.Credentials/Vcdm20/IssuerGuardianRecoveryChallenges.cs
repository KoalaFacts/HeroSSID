using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifier-owned, purpose-separated one-use challenges for issuer guardian
/// recovery. Verification never enrolls or authorizes the successor issuer.
/// </summary>
/// <remarks>
/// The caller supplies a trusted IPresentationChallengeStore. Use a singleton
/// InMemoryPresentationChallengeStore only for one process; use a shared atomic
/// store across replicas. No schema changes are required by this SDK adapter.
/// </remarks>
public static class IssuerGuardianRecoveryChallenges
{
    // Presentation challenges and issuer recovery must NEVER share a purpose.
    // This marker is stored only in verifier-owned challenge metadata; it is
    // not an issuer DID and must not be accepted as a trusted issuer identity.
    private const string RecoveryMarkerPrefix = "herossid:issuer-guardian-recovery:v1:";
    private const string BoundRecoveryMarkerPrefix = "herossid:issuer-guardian-recovery:v2:";

    /// <summary>
    /// Issue a short-lived one-use recovery challenge, bound to the verifier
    /// tenant, HTTPS audience, old issuer and recovery purpose.
    /// The caller must independently authorize who may request recovery.
    /// </summary>
    /// <summary>
    /// Issue an opt-in challenge cryptographically committed to the verifier's
    /// exact pre-enrolled guardian DID set and quorum. A different policy
    /// cannot later redeem the same nonce; this does not enroll guardians.
    /// </summary>
    public static PresentationChallenge IssueBoundToGuardians(IPresentationChallengeStore store,
        Guid verifierTenantId, string trustedPreviousIssuerDid,
        IReadOnlyCollection<string> trustedGuardianDids, int requiredGuardianSignatures,
        Uri verifierAudience, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedGuardianDids);
        ArgumentNullException.ThrowIfNull(verifierAudience);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid, out _) ||
            !ValidAudience(verifierAudience))
        {
            throw new ArgumentException("A pinned old did:key issuer and exact HTTPS verifier audience are required.");
        }

        if (!TryBoundMarker(trustedPreviousIssuerDid, trustedGuardianDids,
                requiredGuardianSignatures, out string marker))
        {
            throw new ArgumentException("Two to five distinct independently trusted guardian DIDs and a valid quorum are required.");
        }

        // The shared challenge table already stores one opaque verifier-owned
        // identifier: a domain-separated SHA-256 guardian-policy commitment.
        return store.Issue(verifierTenantId, verifierAudience.AbsoluteUri, marker, lifetime);
    }

    public static PresentationChallenge Issue(IPresentationChallengeStore store,
        Guid verifierTenantId, string trustedPreviousIssuerDid, Uri verifierAudience,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(verifierAudience);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid, out _) ||
            !ValidAudience(verifierAudience))
        {
            throw new ArgumentException("A pinned old did:key issuer and exact HTTPS verifier audience are required.");
        }

        return store.Issue(verifierTenantId, verifierAudience.AbsoluteUri,
            RecoveryMarkerPrefix + trustedPreviousIssuerDid, lifetime);
    }

    /// <summary>
    /// Cancel a previously issued guardian recovery challenge without producing
    /// recovery evidence. A different issuer or challenge purpose must remain untouched.
    /// </summary>
    public static bool TryCancel(IPresentationChallengeStore store,
        Guid verifierTenantId, string trustedPreviousIssuerDid,
        Uri verifierAudience, string nonce)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(nonce);

        if (verifierTenantId == Guid.Empty ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid, out _) ||
            !ValidAudience(verifierAudience))
        {
            return false;
        }

        string audience = verifierAudience.AbsoluteUri;
        PresentationChallenge? challenge = store.Find(verifierTenantId, audience, nonce);

        // Reuse the immutable, verifier-owned recovery-purpose marker.
        // The same nonce on another protocol/issuer must never be cancelled.
        if (challenge is null ||
            !string.Equals(challenge.Nonce, nonce, StringComparison.Ordinal) ||
            !string.Equals(challenge.Audience, audience, StringComparison.Ordinal) ||
            !MatchesIssuerRecoveryMarker(challenge.TrustedIssuerDid, trustedPreviousIssuerDid))
        {
            return false;
        }

        // Cancellation races genuine proof consumption via the same atomic
        // store operation. Only one may win; no candidate DID is disclosed.
        return store.TryConsume(verifierTenantId, audience, nonce);
    }

    /// <summary>
    /// Verify the genuine successor signature and independent pinned-guardian
    /// quorum, then consume the corresponding recovery-only nonce atomically
    /// before returning a candidate successor DID. Invalid/replayed requests
    /// never disclose the successor. Successful evidence alone NEVER promotes
    /// an issuer DID or grants organization/business authorization.
    /// </summary>
    public static bool TryVerifyAndConsume(IPresentationChallengeStore store,
        Guid verifierTenantId, string evidenceJson, string trustedPreviousIssuerDid,
        IReadOnlyCollection<string> trustedGuardianDids, int requiredGuardianSignatures,
        Uri verifierAudience, string expectedNonce, TimeProvider clock,
        out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(evidenceJson);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedGuardianDids);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(clock);

        successorIssuerDid = string.Empty;

        if (verifierTenantId == Guid.Empty ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid, out _) ||
            !ValidAudience(verifierAudience))
        {
            return false;
        }

        string audience = verifierAudience.AbsoluteUri;
        DateTimeOffset now = clock.GetUtcNow();
        PresentationChallenge? challenge = store.Find(verifierTenantId, audience, expectedNonce);

        // Find is non-consuming; validate purpose and previous-issuer enrollment
        // from trusted STORE state, never from the untrusted recovery envelope.
        if (challenge is null ||
            !string.Equals(challenge.Nonce, expectedNonce, StringComparison.Ordinal) ||
            !string.Equals(challenge.Audience, audience, StringComparison.Ordinal) ||
            !MatchesRecoveryPolicy(challenge.TrustedIssuerDid, trustedPreviousIssuerDid,
                trustedGuardianDids, requiredGuardianSignatures) ||
            challenge.ExpiresAt <= now ||
            !IssuerGuardianRecovery.TryVerify(evidenceJson, trustedPreviousIssuerDid,
                trustedGuardianDids, requiredGuardianSignatures,
                verifierAudience, expectedNonce, now, out string candidate))
        {
            return false;
        }

        // This is the only success gate: the store rechecks live tenant,
        // audience, nonce and expiration in a single atomic consumption.
        // Two concurrent valid proofs cannot both receive the candidate DID.
        if (!store.TryConsume(verifierTenantId, audience, expectedNonce))
        {
            return false;
        }

        successorIssuerDid = candidate;
        return true;
    }

    private static bool MatchesIssuerRecoveryMarker(string stored, string previousIssuerDid)
    {
        if (string.Equals(stored, RecoveryMarkerPrefix + previousIssuerDid,
                StringComparison.Ordinal))
        {
            return true;
        }

        string prefix = BoundRecoveryMarkerPrefix + previousIssuerDid + ":";
        return stored.StartsWith(prefix, StringComparison.Ordinal) &&
            stored.Length == prefix.Length + 64 &&
            stored.AsSpan(prefix.Length).ToString().All(static c =>
                c is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    private static bool MatchesRecoveryPolicy(string stored, string previousIssuerDid,
        IReadOnlyCollection<string> guardians, int threshold) =>
        string.Equals(stored, RecoveryMarkerPrefix + previousIssuerDid,
            StringComparison.Ordinal) ||
        (TryBoundMarker(previousIssuerDid, guardians, threshold, out string bound) &&
            string.Equals(stored, bound, StringComparison.Ordinal));

    private static bool TryBoundMarker(string previousIssuerDid,
        IReadOnlyCollection<string> guardians, int threshold, out string marker)
    {
        marker = string.Empty;
        if (guardians.Count is < 2 or > 5 || threshold < 2 || threshold > guardians.Count)
        {
            return false;
        }

        var pins = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in guardians)
        {
            if (string.IsNullOrWhiteSpace(did) ||
                string.Equals(did, previousIssuerDid, StringComparison.Ordinal) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _) ||
                !pins.Add(did))
            {
                return false;
            }
        }

        string[] ordered = [.. pins.OrderBy(static did => did, StringComparer.Ordinal)];
        // Serialization preserves fixed field order. A sorted, structured
        // encoding avoids concatenation ambiguities and caller array order.
        string policy = JsonSerializer.Serialize(new { threshold, guardianDids = ordered });
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(policy)));
        marker = BoundRecoveryMarkerPrefix + previousIssuerDid + ":" + digest;
        return true;
    }

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2_048;
}
