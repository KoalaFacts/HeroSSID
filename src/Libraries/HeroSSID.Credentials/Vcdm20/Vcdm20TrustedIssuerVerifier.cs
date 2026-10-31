using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Explicit verifier-owned issuer allowlist for a bounded VC2 key transition.
/// Verification never infers issuer trust from the JWT or a successor proof.
/// </summary>
public static class Vcdm20TrustedIssuerVerifier
{
    /// <summary>
    /// Check a direct VC2 JWT against independently enrolled issuer did:key values.
    /// Only the actual validated signer and subject are returned on success.
    /// Neither historical nor successor keys are automatically trusted.
    /// </summary>
    public static bool TryVerify(
        string issuerSignedJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Issuer allowlist verification is not implemented.");
    }
}
