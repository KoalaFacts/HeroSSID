using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Authenticate the original short-lived issuer-signed agent scope, the distinct
/// agent's real one-use holder proof and the same issuer's signed status.
/// Issuer provenance and possession are NOT business authorization, legal
/// identity, consent, or evidence of a live complete revocation inventory.
/// </summary>
public static class Vcdm20AgentScopePresentation
{
    /// <summary>
    /// Requires verifier-owned issuer, agent, resource, action, exact credential
    /// ID, recipient, signed request digest, and minimum status-observation pins.
    /// Only SignedNotListed releases the authenticated scope. A valid holder
    /// proof atomically spends its nonce even when status or scope rejects it.
    /// The host must enforce its own actual business authorization and live
    /// incident policies after this method; this method never executes actions.
    /// </summary>
    public static Vcdm20RevocationCheckResult CheckWithIssuerStatus(
        string presentationJwt, string signedRequestJwt, string trustedRequestSha256,
        string trustedVerifierDid, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string expectedAgentDid, Uri expectedContextUri, Uri expectedCredentialId,
        Uri expectedRecipient, Uri expectedResource, string expectedAction,
        DateTimeOffset minimumObservedAtUtc, IPresentationChallengeStore challenges,
        TimeProvider clock, out JsonElement verifiedScope)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(signedRequestJwt);
        ArgumentNullException.ThrowIfNull(trustedRequestSha256);
        ArgumentNullException.ThrowIfNull(trustedVerifierDid);
        ArgumentNullException.ThrowIfNull(snapshotJwt);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedAgentDid);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedRecipient);
        ArgumentNullException.ThrowIfNull(expectedResource);
        ArgumentNullException.ThrowIfNull(expectedAction);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);

        verifiedScope = default;
        // Do not let an issuer-scoped aud disagree with the intended verifier
        // challenge recipient. Trust comes only from verifier-owned parameters.
        if (!PresentationChallengePolicy.IsValidLookup(
                verifierTenantId, expectedAudience, expectedNonce) ||
            !expectedRecipient.IsAbsoluteUri ||
            !string.Equals(expectedAudience, expectedRecipient.AbsoluteUri,
                StringComparison.Ordinal))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        // The challenge was issued under an already enrolled issuer DID.
        // An untrusted request/holder must not change that trust anchor.
        PresentationChallenge? retained =
            challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        if (retained is null ||
            !string.Equals(retained.TrustedIssuerDid, trustedIssuerDid,
                StringComparison.Ordinal))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        // Reuse the established verifier-request-digest and genuine Ed25519
        // issuer/holder proof, atomic one-use nonce, and exact ORIGINAL JWT
        // same-issuer 60-second signed status check. This call consumes a valid
        // holder challenge before checking status, even if later denied.
        Vcdm20RevocationCheckResult result =
            Vcdm20RevocationSnapshot.CheckRecipientBoundPresentationWithIssuerStatus(
                presentationJwt, signedRequestJwt, trustedRequestSha256,
                trustedVerifierDid, snapshotJwt, verifierTenantId,
                expectedAudience, expectedNonce,
                Vcdm20AgentScopeAssertion.CredentialType, expectedContextUri,
                expectedCredentialId, expectedRecipient, minimumObservedAtUtc,
                challenges, clock, out JsonElement holderVerifiedSubject);
        if (result != Vcdm20RevocationCheckResult.SignedNotListed)
        {
            return result;
        }

        // The enclosing VP has been authenticated above. Never trust a
        // detached or holder-rewritten action: inspect only its exact embedded
        // original issuer-signed credential, then enforce all agent-specific
        // pins and the <=15-minute *signed* scope lifetime.
        if (!Vcdm20RevocationSnapshot.TryExtractEnclosedJwt(
                presentationJwt, out string originalIssuerJwt) ||
            !Vcdm20AgentScopeAssertion.TryVerify(
                originalIssuerJwt, trustedIssuerDid, expectedAgentDid,
                expectedContextUri, expectedCredentialId, expectedRecipient,
                expectedResource, expectedAction, clock.GetUtcNow(),
                out JsonElement issuerVerifiedScope) ||
            !JsonElement.DeepEquals(holderVerifiedSubject, issuerVerifiedScope) ||
            // Recheck both VP and private status expiry at disclosure, after
            // the extra agent-specific verification work has completed.
            !Vcdm20RevocationSnapshot.SignedTokensRemainUnexpiredAtDisclosure(
                presentationJwt, holderVerifiedSubject, snapshotJwt, clock))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        verifiedScope = issuerVerifiedScope;
        return Vcdm20RevocationCheckResult.SignedNotListed;
    }
}
