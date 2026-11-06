using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Opt-in VC 1.1 issuer verification against a verifier-enrolled did:web
/// verification method and exact Ed25519 public key, without remote DID
/// resolution or automatic trust promotion. Not yet implemented.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerVerifier
{
    /// <summary>
    /// Verify an original issuer-signed jwt_vc_json before releasing claims.
    /// Both the DID and verification method/public key must be independently
    /// approved by the relying party; this does not establish identity or authority.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Pinned did:web VC1.1 issuer verification is not implemented.");
    }
}
