using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifies an original directly encoded VC2 JOSE credential from an
/// independently enrolled did:web issuer; neither DID URL nor JWT selects
/// a trusted key. This is issuer signature validation, not holder proof.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Verify an externally pinned did:web Ed25519 assertion method, exact
    /// signed issuer name and HTTPS credential ID before releasing claims.
    /// </summary>
    public static bool TryVerifyPinnedDidWebIssuerNameAndId(
        string jwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        // Test-first RED: no direct VC2 did:web verification exists yet.
        return false;
    }
}
