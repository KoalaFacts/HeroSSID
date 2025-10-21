namespace HeroSSID.Credentials.SdJwt;

/// <summary>
/// Mock interface for SD-JWT (Selective Disclosure for JWTs) generation
/// Based on IETF draft-ietf-oauth-selective-disclosure-jwt-22
/// </summary>
/// <remarks>
/// This is a MOCK interface for MVP development. The actual implementation will come from
/// the HeroSD-JWT NuGet package (https://github.com/BeingCiteable/HeroSD-JWT) when available.
///
/// SD-JWT allows issuers to create credentials where holders can selectively disclose claims
/// to verifiers without revealing all credential data (privacy-preserving).
/// </remarks>
public interface ISdJwtGenerator
{
    /// <summary>
    /// Generates an SD-JWT with selective disclosure capabilities
    /// </summary>
    /// <param name="claims">All claims to include in the credential</param>
    /// <param name="selectiveDisclosureClaims">Claims that should support selective disclosure (will be hashed)</param>
    /// <param name="signingKey">Ed25519 private key for signing (32 or 64 bytes)</param>
    /// <param name="issuerDid">DID identifier of the issuer</param>
    /// <param name="holderDid">DID identifier of the holder</param>
    /// <returns>SD-JWT result with compact format and disclosure tokens</returns>
    /// <remarks>
    /// MOCK IMPLEMENTATION: For MVP, this will return a standard JWT-VC without actual SD-JWT features.
    /// The real HeroSD-JWT library will implement proper hash-based claim disclosures per IETF draft-22.
    /// </remarks>
    public SdJwtResult GenerateSdJwt(
        Dictionary<string, object> claims,
        string[] selectiveDisclosureClaims,
        byte[] signingKey,
        string issuerDid,
        string holderDid);
}
