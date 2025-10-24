using HeroSDJWT;
using HeroSSID.Credentials.SdJwt;
using System.Collections.Generic;

namespace HeroSSID.Credentials.Implementations;

/// <summary>
/// Production implementation of ISdJwtGenerator using HeroSD-JWT NuGet package
/// Implements IETF draft-ietf-oauth-selective-disclosure-jwt specification
/// </summary>
/// <remarks>
/// This implementation uses the HeroSD-JWT library (https://github.com/KoalaFacts/HeroSD-JWT)
/// to provide proper hash-based selective disclosure capabilities per IETF draft-22.
///
/// SD-JWT allows issuers to create credentials where holders can selectively disclose claims
/// to verifiers without revealing all credential data (privacy-preserving).
/// </remarks>
public sealed class HeroSdJwtGenerator : ISdJwtGenerator
{
    /// <summary>
    /// Generates an SD-JWT with selective disclosure capabilities using HeroSD-JWT library
    /// </summary>
    /// <param name="claims">All claims to include in the credential</param>
    /// <param name="selectiveDisclosureClaims">Claims that should support selective disclosure (will be hashed)</param>
    /// <param name="signingKey">Ed25519 private key for signing (32 or 64 bytes)</param>
    /// <param name="issuerDid">DID identifier of the issuer</param>
    /// <param name="holderDid">DID identifier of the holder</param>
    /// <returns>SD-JWT result with compact format and disclosure tokens</returns>
    /// <remarks>
    /// This implementation creates proper SD-JWT credentials with:
    /// - Hash-based claim disclosures per IETF draft-22
    /// - _sd array in JWT payload containing SHA-256 digests
    /// - Separate disclosure tokens for selective presentation
    /// </remarks>
    public SdJwtResult GenerateSdJwt(
        Dictionary<string, object> claims,
        string[] selectiveDisclosureClaims,
        byte[] signingKey,
        string issuerDid,
        string holderDid)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(selectiveDisclosureClaims);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrEmpty(issuerDid);
        ArgumentException.ThrowIfNullOrEmpty(holderDid);

        // Create SD-JWT using HeroSD-JWT library
        var generator = new SdJwtGenerator();

        // Configure the generator with issuer and subject
        var options = new SdJwtOptions
        {
            Issuer = issuerDid,
            Subject = holderDid,
            SelectiveDisclosureClaims = selectiveDisclosureClaims
        };

        // Generate the SD-JWT with selective disclosure
        var sdJwtToken = generator.Generate(
            claims: claims,
            signingKey: signingKey,
            options: options);

        // Convert HeroSD-JWT result to our SdJwtResult format
        return new SdJwtResult
        {
            CompactSdJwt = sdJwtToken.CompactSerialization,
            DisclosureTokens = sdJwtToken.Disclosures.ToArray(),
            ClaimDigests = sdJwtToken.ClaimDigests
        };
    }
}
