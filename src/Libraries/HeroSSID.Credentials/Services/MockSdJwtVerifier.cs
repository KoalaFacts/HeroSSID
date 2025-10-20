using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Models;
using HeroSSID.Credentials.Utilities;
using System.Text.Json;

namespace HeroSSID.Credentials.Services;

/// <summary>
/// Mock implementation of ISdJwtVerifier for MVP development
/// Verifies standard JWT-VC without actual SD-JWT selective disclosure validation
/// </summary>
/// <remarks>
/// TEMPORARY IMPLEMENTATION for MVP. This will be replaced by the actual HeroSD-JWT
/// NuGet package (https://github.com/BeingCiteable/HeroSD-JWT) which implements
/// proper hash-based selective disclosure verification per IETF draft-22.
///
/// Current behavior: Verifies standard JWT-VC signature only.
/// Future behavior: Will validate disclosure tokens against hash digests in JWT's _sd array.
/// </remarks>
public sealed class MockSdJwtVerifier : ISdJwtVerifier
{
    /// <summary>
    /// Verifies a mock SD-JWT (actually a standard JWT-VC for MVP)
    /// </summary>
    public SdJwtVerificationResult VerifySdJwt(
        string compactSdJwt,
        string[] selectedDisclosures,
        byte[] issuerPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactSdJwt);
        ArgumentNullException.ThrowIfNull(selectedDisclosures);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);

        // MOCK: For MVP, extract JWT from compact format (jwt~disclosures~)
        // The actual HeroSD-JWT library will parse and validate disclosure tokens
        var jwtPart = compactSdJwt.Split('~')[0];

        // Verify JWT signature
        var isSignatureValid = Ed25519JwtSigner.VerifySignedJwt(jwtPart, issuerPublicKey);

        if (!isSignatureValid)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.SignatureInvalid,
                ValidationErrors = new[] { "JWT signature verification failed" }
            };
        }

        // Parse JWT payload to extract claims
        try
        {
            var payloadJson = Ed25519JwtSigner.ExtractPayload(jwtPart);
            var payload = JsonDocument.Parse(payloadJson);

            string? issuerDid = null;
            string? holderDid = null;
            Dictionary<string, object>? disclosedClaims = null;

            // Extract issuer and subject DIDs
            if (payload.RootElement.TryGetProperty("iss", out var iss))
            {
                issuerDid = iss.GetString();
            }

            if (payload.RootElement.TryGetProperty("sub", out var sub))
            {
                holderDid = sub.GetString();
            }

            // Extract credential subject claims
            if (payload.RootElement.TryGetProperty("vc", out var vc) &&
                vc.TryGetProperty("credentialSubject", out var credentialSubject))
            {
                var claimsJson = credentialSubject.GetRawText();
                disclosedClaims = JsonSerializer.Deserialize<Dictionary<string, object>>(claimsJson);
            }

            return new SdJwtVerificationResult
            {
                IsValid = true,
                Status = SdJwtVerificationStatus.Valid,
                ValidationErrors = Array.Empty<string>(),
                DisclosedClaims = disclosedClaims,
                IssuerDid = issuerDid,
                HolderDid = holderDid
            };
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.MalformedSdJwt,
                ValidationErrors = new[] { "Failed to parse SD-JWT payload" }
            };
        }
    }
}
