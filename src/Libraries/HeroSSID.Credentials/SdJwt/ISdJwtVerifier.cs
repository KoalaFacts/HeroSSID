namespace HeroSSID.Credentials.SdJwt;

/// <summary>
/// Mock interface for SD-JWT (Selective Disclosure for JWTs) verification
/// Based on IETF draft-ietf-oauth-selective-disclosure-jwt-22
/// </summary>
/// <remarks>
/// This is a MOCK interface for MVP development. The actual implementation will come from
/// the HeroSD-JWT NuGet package (https://github.com/KoalaFacts/HeroSD-JWT) when available.
///
/// Verifiers use this to validate SD-JWT credentials and reconstruct disclosed claims.
/// </remarks>
public interface ISdJwtVerifier
{
    /// <summary>
    /// Verifies an SD-JWT and reconstructs the disclosed claims
    /// </summary>
    /// <param name="compactSdJwt">SD-JWT in compact format: jwt~disclosure1~disclosure2~...~</param>
    /// <param name="selectedDisclosures">Disclosure tokens selected by holder for this presentation</param>
    /// <param name="issuerPublicKey">Ed25519 public key of the issuer (32 bytes)</param>
    /// <returns>Verification result with reconstructed claims</returns>
    /// <remarks>
    /// MOCK IMPLEMENTATION: For MVP, this will verify a standard JWT-VC without actual SD-JWT features.
    /// The real HeroSD-JWT library will:
    /// 1. Verify JWT signature using issuer's public key
    /// 2. Validate disclosure tokens against JWT hash digests (_sd array)
    /// 3. Reconstruct full credential with disclosed claims only
    /// </remarks>
    public SdJwtVerificationResult VerifySdJwt(
        string compactSdJwt,
        string[] selectedDisclosures,
        byte[] issuerPublicKey);
}
