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

    /// <summary>
    /// Issue a short-lived one-use recovery challenge, bound to the verifier
    /// tenant, HTTPS audience, old issuer and recovery purpose.
    /// The caller must independently authorize who may request recovery.
    /// </summary>
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

        throw new NotSupportedException("Recovery challenge cancellation is not implemented.");
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
            !string.Equals(challenge.TrustedIssuerDid,
                RecoveryMarkerPrefix + trustedPreviousIssuerDid, StringComparison.Ordinal) ||
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

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2_048;
}
