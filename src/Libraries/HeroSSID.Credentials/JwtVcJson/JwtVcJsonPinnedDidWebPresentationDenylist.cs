using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Verifier-owned, exact-original-JWT emergency denial of a holder-bound did:web VC1.1 proof.</summary>
public enum JwtVcJsonPinnedDidWebDenylistResult
{
    /// <summary>Invalid proof, issuer pin, verifier challenge or local denial policy.</summary>
    Invalid,

    /// <summary>Authentic holder and issuer signatures, but the verifier has blocked this exact credential JWT.</summary>
    DeniedByVerifier,

    /// <summary>Authentic issuer and holder signatures plus one-use proof; issuer revocation status remains unchecked.</summary>
    SignedButStatusUnchecked
}

/// <summary>
/// Optional independently maintained verifier emergency blocklist, not issuer
/// revocation, an identity check, business authorization or consent evidence.
/// </summary>
public static class JwtVcJsonPinnedDidWebPresentationDenylist
{
    /// <summary>
    /// Verify both real signatures, independently pinned did:web issuer metadata,
    /// a one-use challenge, and the entire exact original-credential SHA-256 policy
    /// before releasing claims. A valid denied proof must consume its nonce too.
    /// </summary>
    public static JwtVcJsonPinnedDidWebDenylistResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        throw new NotSupportedException("Red-phase runtime stub: emergency denial is not yet implemented.");
    }
}
