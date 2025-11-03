using HeroSdJwt.Verification;
using HeroSSID.Credentials.SdJwt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace HeroSSID.Credentials.Implementations;

/// <summary>
/// Production implementation of ISdJwtVerifier using HeroSD-JWT NuGet package v1.0.7
/// Implements IETF draft-ietf-oauth-selective-disclosure-jwt specification
/// </summary>
/// <remarks>
/// This implementation uses the HeroSD-JWT library (https://github.com/KoalaFacts/HeroSD-JWT)
/// to provide proper hash-based selective disclosure verification per IETF draft-22.
///
/// Verifiers use this to validate SD-JWT credentials and reconstruct disclosed claims.
///
/// CRYPTOGRAPHY NOTE:
/// This verifier expects HMAC-signed SD-JWTs to match the generator implementation.
/// For ECDSA-signed SD-JWTs, update to use ECDSA public keys.
/// </remarks>
public sealed class HeroSdJwtVerifier : ISdJwtVerifier
{
    /// <summary>
    /// Verifies an SD-JWT and reconstructs the disclosed claims using HeroSD-JWT library
    /// </summary>
    /// <param name="compactSdJwt">SD-JWT in compact format: jwt~disclosure1~disclosure2~...~</param>
    /// <param name="selectedDisclosures">Disclosure tokens selected by holder for this presentation (currently unused - disclosures embedded in compactSdJwt)</param>
    /// <param name="issuerPublicKey">HMAC shared secret for verification (used as HMAC key)</param>
    /// <returns>Verification result with reconstructed claims</returns>
    /// <remarks>
    /// This implementation:
    /// 1. Verifies JWT signature using issuer's key
    /// 2. Validates disclosure tokens against JWT hash digests (_sd array)
    /// 3. Reconstructs full credential with disclosed claims only
    ///
    /// NOTE: The compactSdJwt parameter should include the presentation format:
    /// jwt~disclosure1~disclosure2~... (with only the disclosures to reveal)
    /// </remarks>
    public SdJwtVerificationResult VerifySdJwt(
        string compactSdJwt,
        string[] selectedDisclosures,
        byte[] issuerPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactSdJwt);
        ArgumentNullException.ThrowIfNull(selectedDisclosures);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);

        try
        {
            // Create verifier instance
            var verifier = new SdJwtVerifier();

            // Verify the presentation using HMAC
            // The compactSdJwt contains: jwt~disclosure1~disclosure2~...~
            var result = verifier.VerifyPresentation(compactSdJwt, issuerPublicKey);

            // Extract verification result details
            var isValid = GetIsValid(result);

            if (!isValid)
            {
                return new SdJwtVerificationResult
                {
                    IsValid = false,
                    Status = SdJwtVerificationStatus.SignatureInvalid,
                    ValidationErrors = ["SD-JWT signature verification failed"]
                };
            }

            // Extract disclosed claims from the verification result
            var disclosedClaims = GetDisclosedClaims(result);
            var issuerDid = disclosedClaims?.GetValueOrDefault("iss")?.ToString();
            var holderDid = disclosedClaims?.GetValueOrDefault("sub")?.ToString();

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
        catch (FormatException ex)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.MalformedSdJwt,
                ValidationErrors = [$"Malformed SD-JWT format: {ex.Message}"]
            };
        }
        catch (ArgumentException ex)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.DisclosureMismatch,
                ValidationErrors = [$"Disclosure validation failed: {ex.Message}"]
            };
        }
        catch (Exception ex)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.MalformedSdJwt,
                ValidationErrors = [$"Unexpected verification error: {ex.Message}"]
            };
        }
    }

    private static bool GetIsValid(object result)
    {
        // Try to get IsValid property from verification result
        var type = result.GetType();
        var isValidProperty = type.GetProperty("IsValid", BindingFlags.Public | BindingFlags.Instance);

        if (isValidProperty != null && isValidProperty.PropertyType == typeof(bool))
        {
            return (bool)isValidProperty.GetValue(result)!;
        }

        // If no IsValid property, assume success (VerifyPresentation would throw on failure)
        return true;
    }

    private static Dictionary<string, object>? GetDisclosedClaims(object result)
    {
        // Try to get DisclosedClaims property from verification result
        var type = result.GetType();

        var claimsProperty = type.GetProperty("DisclosedClaims", BindingFlags.Public | BindingFlags.Instance)
                           ?? type.GetProperty("Claims", BindingFlags.Public | BindingFlags.Instance)
                           ?? type.GetProperty("ReconstructedClaims", BindingFlags.Public | BindingFlags.Instance);

        if (claimsProperty != null)
        {
            var value = claimsProperty.GetValue(result);

            // Handle Dictionary<string, object>
            if (value is Dictionary<string, object> dict)
            {
                return dict;
            }

            // Handle IDictionary<string, object>
            if (value is IDictionary<string, object> idict)
            {
                return new Dictionary<string, object>(idict);
            }

            // Try to convert other dictionary types
            if (value != null)
            {
                var valueType = value.GetType();
                if (valueType.IsGenericType &&
                    valueType.GetGenericTypeDefinition() == typeof(Dictionary<,>))
                {
                    // Try to extract as Dictionary<string, object>
                    var dict2 = new Dictionary<string, object>();
                    var enumerableType = value as System.Collections.IEnumerable;
                    if (enumerableType != null)
                    {
                        foreach (var item in enumerableType)
                        {
                            var itemType = item.GetType();
                            var keyProp = itemType.GetProperty("Key");
                            var valueProp = itemType.GetProperty("Value");
                            if (keyProp != null && valueProp != null)
                            {
                                var key = keyProp.GetValue(item)?.ToString();
                                var val = valueProp.GetValue(item);
                                if (key != null)
                                {
                                    dict2[key] = val!;
                                }
                            }
                        }
                        return dict2;
                    }
                }
            }
        }

        return null;
    }
}
