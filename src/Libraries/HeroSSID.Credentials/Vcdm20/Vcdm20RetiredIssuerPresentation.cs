using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Retired-issuer policy combined with holder Ed25519 proof and an atomic
/// verifier-owned one-use challenge. A signature is not real-world identity
/// verification, holder consent or business authorization.
/// </summary>
public static class Vcdm20RetiredIssuerPresentation
{
    /// <summary>
    /// Validate a full-disclosure holder-signed direct VC2 presentation and then
    /// independently require active issuer trust or an exact historical JWT pin.
    /// A challenge spent by a valid holder proof cannot be replayed even if
    /// the verifier's independent retirement policy rejects the credential.
    /// </summary>
    public static Vcdm20VerifierPolicyResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        TimeProvider clock, out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        CheckCore(presentationJwt, null, verifierTenantId, expectedAudience,
            expectedNonce, expectedCredentialType, expectedContextUri, challenges,
            activeIssuerDids, retiredCredentialPins, clock,
            out verifiedIssuerDid, out verifiedSubject);

    /// <summary>
    /// Additionally require an authentic, short-lived private revocation status
    /// from the actual signer; clean issuer status is not proof of live clearance.
    /// </summary>
    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string presentationJwt, string revocationSnapshotJwt,
        Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        TimeProvider clock, out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        return CheckCore(presentationJwt, revocationSnapshotJwt,
            verifierTenantId, expectedAudience, expectedNonce,
            expectedCredentialType, expectedContextUri, challenges,
            activeIssuerDids, retiredCredentialPins, clock,
            out verifiedIssuerDid, out verifiedSubject);
    }

    private static Vcdm20VerifierPolicyResult CheckCore(
        string presentationJwt, string? revocationSnapshotJwt,
        Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        TimeProvider clock, out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(activeIssuerDids);
        ArgumentNullException.ThrowIfNull(retiredCredentialPins);
        ArgumentNullException.ThrowIfNull(clock);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // The existing one-use presentation verifier checks the tenant-owned
        // challenge's pinned issuer DID, actual holder and issuer Ed25519
        // signatures, original credential, audience, nonce, policy and expiry.
        // It atomically spends the challenge before releasing authenticated
        // artifacts to the additional independent retirement policy.
        if (Vcdm20JosePresentation.CheckWithAuthenticatedOriginal(
                presentationJwt, verifierTenantId, expectedAudience,
                expectedNonce, expectedCredentialType, expectedContextUri,
                challenges, clock, out _, out string originalCredentialJwt,
                out string authenticatedHolderDid) !=
            Vcdm20PresentationCheckResult.SignedButStatusUnchecked)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        // A successful holder proof alone cannot bypass a verifier's active or
        // retired issuer policy. Reverify the exact original signed VC2 JWT
        // against independently enrolled issuer DIDs and original hashes,
        // using the actual authenticated holder DID. The challenge stays
        // consumed when an independent policy or status rejects the proof.
        DateTimeOffset now = clock.GetUtcNow();
        Vcdm20VerifierPolicyResult result = revocationSnapshotJwt is null
            ? Vcdm20RetiredIssuerVerifier.Check(
                originalCredentialJwt, activeIssuerDids, retiredCredentialPins,
                authenticatedHolderDid, expectedCredentialType,
                expectedContextUri, now, out string issuer, out JsonElement subject)
            : Vcdm20RetiredIssuerVerifier.CheckWithStatus(
                originalCredentialJwt, revocationSnapshotJwt, activeIssuerDids,
                retiredCredentialPins, authenticatedHolderDid,
                expectedCredentialType, expectedContextUri, now,
                out issuer, out subject);

        if (result is Vcdm20VerifierPolicyResult.SignedButStatusUnchecked or
            Vcdm20VerifierPolicyResult.SignedNotListed)
        {
            verifiedIssuerDid = issuer;
            verifiedSubject = subject;
        }

        return result;
    }
}
