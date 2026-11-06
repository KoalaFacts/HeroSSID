using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Opt-in full-disclosure SDK holder presentation of an original did:web issuer-signed
/// VC1.1 JWT. An application MUST authenticate the challenge out of band and obtain
/// informed holder consent. Neither the challenge nor a JWT enrolls issuer trust.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerPresentation
{
    /// <summary>
    /// Create a real holder-signed VP for an application-authenticated challenge
    /// after independently pinning the issuer's method, key, name and credential ID.
    /// This is not a signed OpenID4VP request or third-party wallet exchange.
    /// </summary>
    public static string Create(
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid, byte[] holderSeed,
        TimeProvider clock) =>
        throw new NotSupportedException("RED: did:web issuer to holder VP not implemented.");

    /// <summary>
    /// Verify the issuer's original JWT and holder's independent Ed25519 VP,
    /// then atomically consume one verifier-owned nonce before disclosing claims.
    /// An authentic signature does not establish identity, consent or authority.
    /// </summary>
    public static JwtVcJsonPresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject) =>
        throw new NotSupportedException("RED: did:web issuer to holder VP not implemented.");
}
