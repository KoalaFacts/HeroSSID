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
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Corrected RED: signed-ID holder claim policy intentionally unimplemented.");
    }
}
