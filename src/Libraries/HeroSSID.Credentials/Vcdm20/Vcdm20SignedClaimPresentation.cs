using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in full-disclosure holder proof plus an independently pinned exact
/// issuer-signed membership claim policy. Does not grant business authority.
/// </summary>
public static class Vcdm20SignedClaimPresentation
{
    /// <summary>
    /// Verifies a holder's genuine Ed25519-signed, one-use presentation and
    /// its unchanged original VC2 JWT before enforcing verifier-supplied
    /// issuer pins, exact credential ID, subject DID, and string claims.
    /// The valid holder challenge is spent even if the separate claim policy
    /// rejects it. A valid result does not prove current non-revocation.
    /// </summary>
    public static Vcdm20PresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredSubjectClaims,
        TimeProvider clock, out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(requiredSubjectClaims);
        ArgumentNullException.ThrowIfNull(clock);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // This inner verifier validates both issuer and holder Ed25519
        // signatures against the verifier-owned challenge's pinned issuer,
        // nonce, audience, tenant and expiry, and atomically consumes it.
        // It returns the original issuer-signed credential and actual holder
        // only after successful one-use verification.
        if (Vcdm20JosePresentation.CheckWithAuthenticatedOriginalSignedId(
                presentationJwt, verifierTenantId, expectedAudience,
                expectedNonce, expectedCredentialType, expectedContextUri,
                expectedCredentialId, challenges, clock, out _, out string originalCredentialJwt,
                out string actualHolderDid) !=
            Vcdm20PresentationCheckResult.SignedButStatusUnchecked ||
            !string.Equals(actualHolderDid, expectedHolderDid,
                StringComparison.Ordinal))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        // Recheck the original JWT with an INDEPENDENT issuer allowlist,
        // the verifier-pinned top-level credential ID, the exact holder,
        // context, type, lifetime and 1–16 exact string claims. No subject
        // escapes if even one check fails. This is not a status lookup or
        // an entitlement decision.
        if (!Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
                originalCredentialJwt, trustedIssuerDids, expectedHolderDid,
                expectedCredentialType, expectedContextUri,
                expectedCredentialId, requiredSubjectClaims, clock.GetUtcNow(),
                out string issuer, out JsonElement subject))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        verifiedIssuerDid = issuer;
        verifiedSubject = subject;
        return Vcdm20PresentationCheckResult.SignedButStatusUnchecked;
    }
}
