using HeroSDJWT;
using HeroSSID.Credentials.SdJwt;
using System;
using System.Linq;

namespace HeroSSID.Credentials.Implementations;

/// <summary>
/// Production implementation of ISdJwtVerifier using HeroSD-JWT NuGet package
/// Implements IETF draft-ietf-oauth-selective-disclosure-jwt specification
/// </summary>
/// <remarks>
/// This implementation uses the HeroSD-JWT library (https://github.com/KoalaFacts/HeroSD-JWT)
/// to provide proper hash-based selective disclosure verification per IETF draft-22.
///
/// Verifiers use this to validate SD-JWT credentials and reconstruct disclosed claims.
/// </remarks>
public sealed class HeroSdJwtVerifier : ISdJwtVerifier
{
    /// <summary>
    /// Verifies an SD-JWT and reconstructs the disclosed claims using HeroSD-JWT library
    /// </summary>
    /// <param name="compactSdJwt">SD-JWT in compact format: jwt~disclosure1~disclosure2~...~</param>
    /// <param name="selectedDisclosures">Disclosure tokens selected by holder for this presentation</param>
    /// <param name="issuerPublicKey">Ed25519 public key of the issuer (32 bytes)</param>
    /// <returns>Verification result with reconstructed claims</returns>
    /// <remarks>
    /// This implementation:
    /// 1. Verifies JWT signature using issuer's public key
    /// 2. Validates disclosure tokens against JWT hash digests (_sd array)
    /// 3. Reconstructs full credential with disclosed claims only
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
            // Create SD-JWT verifier using HeroSD-JWT library
            var verifier = new SdJwtVerifier();

            // Verify the SD-JWT with selected disclosures
            var verificationResult = verifier.Verify(
                compactSdJwt: compactSdJwt,
                publicKey: issuerPublicKey,
                selectedDisclosures: selectedDisclosures);

            // Check verification status
            if (!verificationResult.IsValid)
            {
                return MapVerificationResult(verificationResult);
            }

            // Successful verification - extract claims
            return new SdJwtVerificationResult
            {
                IsValid = true,
                Status = SdJwtVerificationStatus.Valid,
                ValidationErrors = Array.Empty<string>(),
                DisclosedClaims = verificationResult.DisclosedClaims,
                IssuerDid = verificationResult.Issuer,
                HolderDid = verificationResult.Subject
            };
        }
        catch (SdJwtException ex) when (ex.ErrorCode == SdJwtErrorCode.InvalidSignature)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.SignatureInvalid,
                ValidationErrors = [ex.Message]
            };
        }
        catch (SdJwtException ex) when (ex.ErrorCode == SdJwtErrorCode.DisclosureMismatch)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.DisclosureMismatch,
                ValidationErrors = [ex.Message]
            };
        }
        catch (SdJwtException ex) when (ex.ErrorCode == SdJwtErrorCode.MalformedToken)
        {
            return new SdJwtVerificationResult
            {
                IsValid = false,
                Status = SdJwtVerificationStatus.MalformedSdJwt,
                ValidationErrors = [ex.Message]
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

    private static SdJwtVerificationResult MapVerificationResult(HeroSDJWT.VerificationResult result)
    {
        var status = result.ErrorCode switch
        {
            SdJwtErrorCode.InvalidSignature => SdJwtVerificationStatus.SignatureInvalid,
            SdJwtErrorCode.DisclosureMismatch => SdJwtVerificationStatus.DisclosureMismatch,
            SdJwtErrorCode.MalformedToken => SdJwtVerificationStatus.MalformedSdJwt,
            SdJwtErrorCode.IssuerNotFound => SdJwtVerificationStatus.IssuerNotFound,
            _ => SdJwtVerificationStatus.MalformedSdJwt
        };

        return new SdJwtVerificationResult
        {
            IsValid = false,
            Status = status,
            ValidationErrors = result.Errors?.ToArray() ?? Array.Empty<string>()
        };
    }
}
