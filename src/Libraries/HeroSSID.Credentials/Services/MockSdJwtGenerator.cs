using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Models;
using HeroSSID.Credentials.Utilities;
using System.Text.Json;

namespace HeroSSID.Credentials.Services;

/// <summary>
/// Mock implementation of ISdJwtGenerator for MVP development
/// Generates standard JWT-VC without actual SD-JWT selective disclosure features
/// </summary>
/// <remarks>
/// TEMPORARY IMPLEMENTATION for MVP. This will be replaced by the actual HeroSD-JWT
/// NuGet package (https://github.com/BeingCiteable/HeroSD-JWT) which implements
/// proper hash-based selective disclosure per IETF draft-22.
///
/// Current behavior: Returns a standard JWT-VC with all claims visible.
/// Future behavior: Will create JWT with hashed claims (_sd array) and separate disclosure tokens.
/// </remarks>
public sealed class MockSdJwtGenerator : ISdJwtGenerator
{
    private static readonly string[] W3cVcContext = new[] { "https://www.w3.org/2018/credentials/v1" };
    private static readonly string[] VerifiableCredentialType = new[] { "VerifiableCredential" };

    /// <summary>
    /// Generates a mock SD-JWT (actually a standard JWT-VC for MVP)
    /// </summary>
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

        // MOCK: For MVP, we just create a standard JWT-VC without SD-JWT features
        // The actual HeroSD-JWT library will implement proper selective disclosure

        // Create JWT header
        var header = JsonSerializer.Serialize(new
        {
            typ = "vc+jwt",
            alg = "EdDSA"
        });

        // Create JWT payload with W3C VC structure
        var payload = JsonSerializer.Serialize(new
        {
            iss = issuerDid,
            sub = holderDid,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            vc = new
            {
                context = W3cVcContext,
                type = VerifiableCredentialType,
                credentialSubject = claims
            }
        });

        // Sign the JWT
        var jwt = Ed25519JwtSigner.CreateSignedJwt(header, payload, signingKey);

        // MOCK: Return empty disclosure tokens (real implementation will have actual disclosures)
        // Format would be: jwt~disclosure1~disclosure2~...~
        var compactSdJwt = $"{jwt}~"; // Single trailing tilde indicates no disclosures in mock

        // MOCK: Return empty arrays (real implementation will generate disclosure tokens)
        return new SdJwtResult
        {
            CompactSdJwt = compactSdJwt,
            DisclosureTokens = Array.Empty<string>(),
            ClaimDigests = new Dictionary<string, string>()
        };
    }
}
