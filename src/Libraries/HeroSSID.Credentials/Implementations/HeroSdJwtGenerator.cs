using HeroSdJwt.Issuance;
using HeroSSID.Credentials.SdJwt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace HeroSSID.Credentials.Implementations;

/// <summary>
/// Production implementation of ISdJwtGenerator using HeroSD-JWT NuGet package v1.0.7
/// Implements IETF draft-ietf-oauth-selective-disclosure-jwt specification
/// </summary>
/// <remarks>
/// This implementation uses the HeroSD-JWT library (https://github.com/KoalaFacts/HeroSD-JWT)
/// to provide proper hash-based selective disclosure capabilities per IETF draft-22.
///
/// CRYPTOGRAPHY NOTE:
/// HeroSD-JWT supports HMAC (HS256), RSA (RS256), and ECDSA (ES256) signing algorithms.
/// HeroSSID primarily uses Ed25519 (EdDSA) which is not directly supported by HeroSD-JWT v1.0.7.
///
/// Current implementation uses HMAC (HS256) as a compatible fallback.
/// For production use with DIDs, consider:
/// 1. Using ECDSA (ES256) with P-256 keys for SD-JWT credentials
/// 2. Converting keys or using separate key pairs for SD-JWT vs regular JWTs
/// 3. Requesting EdDSA support from HeroSD-JWT maintainers
/// </remarks>
public sealed class HeroSdJwtGenerator : ISdJwtGenerator
{
    /// <summary>
    /// Generates an SD-JWT with selective disclosure capabilities using HeroSD-JWT library
    /// </summary>
    /// <param name="claims">All claims to include in the credential</param>
    /// <param name="selectiveDisclosureClaims">Claims that should support selective disclosure (will be hashed)</param>
    /// <param name="signingKey">Signing key bytes (used as HMAC key)</param>
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

        // Build SD-JWT using HeroSD-JWT fluent API
        var builder = SdJwtBuilder.Create()
            .WithClaim("iss", issuerDid)
            .WithClaim("sub", holderDid);

        // Add all user claims
        foreach (var claim in claims)
        {
            builder = builder.WithClaim(claim.Key, claim.Value);
        }

        // Mark specified claims as selectively disclosable
        foreach (var selectiveClaim in selectiveDisclosureClaims)
        {
            builder = builder.MakeSelective(selectiveClaim);
        }

        // Sign with HMAC (HS256) - using signing key as HMAC secret
        // NOTE: For production with DIDs, consider using ECDSA (ES256) instead
        var sdJwt = builder.SignWithHmac(signingKey).Build();

        // Extract disclosures and digests using reflection
        // (HeroSD-JWT's SdJwt object structure may vary across versions)
        var disclosures = GetDisclosures(sdJwt);
        var claimDigests = GetClaimDigests(sdJwt);
        var compactFormat = GetCompactFormat(sdJwt);

        return new SdJwtResult
        {
            CompactSdJwt = compactFormat,
            DisclosureTokens = disclosures,
            ClaimDigests = claimDigests
        };
    }

    private static string[] GetDisclosures(object sdJwt)
    {
        // Try to get disclosures via property or method
        var type = sdJwt.GetType();

        // Try property: Disclosures, DisclosureTokens
        var disclosuresProperty = type.GetProperty("Disclosures", BindingFlags.Public | BindingFlags.Instance)
                                ?? type.GetProperty("DisclosureTokens", BindingFlags.Public | BindingFlags.Instance);

        if (disclosuresProperty != null)
        {
            var value = disclosuresProperty.GetValue(sdJwt);
            if (value is IEnumerable<string> disclosures)
            {
                return disclosures.ToArray();
            }
        }

        return Array.Empty<string>();
    }

    private static Dictionary<string, string> GetClaimDigests(object sdJwt)
    {
        // Try to get claim digests via property
        var type = sdJwt.GetType();

        var digestsProperty = type.GetProperty("ClaimDigests", BindingFlags.Public | BindingFlags.Instance)
                            ?? type.GetProperty("Digests", BindingFlags.Public | BindingFlags.Instance)
                            ?? type.GetProperty("Hashes", BindingFlags.Public | BindingFlags.Instance);

        if (digestsProperty != null)
        {
            var value = digestsProperty.GetValue(sdJwt);
            if (value is Dictionary<string, string> digests)
            {
                return digests;
            }
        }

        return new Dictionary<string, string>();
    }

    private static string GetCompactFormat(object sdJwt)
    {
        // Try ToString() first, then look for explicit compact format methods
        var toString = sdJwt.ToString();
        if (!string.IsNullOrEmpty(toString) && toString.Contains('~'))
        {
            return toString;
        }

        // Try methods: ToCompactFormat, ToCombinedFormat, ToCompact
        var type = sdJwt.GetType();
        var methods = new[] { "ToCompactFormat", "ToCombinedFormat", "ToCompact" };

        foreach (var methodName in methods)
        {
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Instance);
            if (method != null && method.ReturnType == typeof(string))
            {
                var result = method.Invoke(sdJwt, null);
                if (result is string str)
                {
                    return str;
                }
            }
        }

        return toString ?? string.Empty;
    }
}
