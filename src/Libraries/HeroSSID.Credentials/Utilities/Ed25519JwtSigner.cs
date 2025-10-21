using NSec.Cryptography;
using System;
using System.Security.Cryptography;
using System.Text;

namespace HeroSSID.Credentials.Utilities;

/// <summary>
/// Utility for creating and verifying Ed25519-signed JWTs
/// Uses NSec.Cryptography for Ed25519 operations (no external JWT libraries)
/// </summary>
public static class Ed25519JwtSigner
{
    private static readonly SignatureAlgorithm Ed25519Algorithm = SignatureAlgorithm.Ed25519;

    /// <summary>
    /// Creates a signed JWT using Ed25519
    /// </summary>
    /// <param name="header">JWT header JSON (without encoding)</param>
    /// <param name="payload">JWT payload JSON (without encoding)</param>
    /// <param name="privateKeyBytes">32-byte Ed25519 private key (seed format)</param>
    /// <returns>Signed JWT in format: {header}.{payload}.{signature}</returns>
    public static string CreateSignedJwt(string header, string payload, byte[] privateKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(privateKeyBytes);

        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(privateKeyBytes));
        }

        // Base64Url encode header and payload
        var headerBase64 = Base64UrlEncoder.Encode(header);
        var payloadBase64 = Base64UrlEncoder.Encode(payload);

        // Create signing input: {header}.{payload}
        var signingInput = $"{headerBase64}.{payloadBase64}";
        var signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

        // Import private key using NSec
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Import(Ed25519Algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey, keyParams);

        // Sign the input
        var signatureBytes = Ed25519Algorithm.Sign(key, signingInputBytes);

        // Base64Url encode signature
        var signatureBase64 = Base64UrlEncoder.Encode(signatureBytes);

        // Return complete JWT
        return $"{signingInput}.{signatureBase64}";
    }

    /// <summary>
    /// Verifies an Ed25519-signed JWT with timing attack resistance
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <param name="publicKeyBytes">32-byte Ed25519 public key</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    /// <remarks>
    /// SECURITY - Timing Attack Mitigation:
    /// This implementation is resistant to timing attacks because:
    /// 1. NSec's Ed25519Algorithm.Verify() uses constant-time signature verification internally
    /// 2. All comparison operations on cryptographic material happen inside NSec's constant-time code
    /// 3. Early returns occur only for obvious format errors (JWT structure, key length), not cryptographic comparison
    /// 4. The try-catch ensures consistent behavior regardless of verification failure reason
    ///
    /// References:
    /// - NSec uses libsodium which implements Ed25519 in constant time
    /// - Ed25519 signature verification is inherently constant-time in proper implementations
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Verification method - any exception means invalid JWT")]
    public static bool VerifySignedJwt(string jwt, byte[] publicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(publicKeyBytes);

        if (publicKeyBytes.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(publicKeyBytes));
        }

        try
        {
            // Split JWT into parts
            var parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                return false; // Malformed JWT (format error, not timing-sensitive)
            }

            // Reconstruct signing input: {header}.{payload}
            var signingInput = $"{parts[0]}.{parts[1]}";
            var signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            // Decode signature
            var signatureBytes = Base64UrlEncoder.DecodeBytes(parts[2]);

            // Import public key using NSec (PublicKey is not IDisposable, no using statement needed)
            var publicKey = PublicKey.Import(Ed25519Algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);

            // SECURITY: NSec's Ed25519Algorithm.Verify() uses constant-time comparison
            // This prevents timing attacks where attackers could learn about the signature
            // by measuring how long verification takes
            return Ed25519Algorithm.Verify(publicKey, signingInputBytes, signatureBytes);
        }
        catch
        {
            // Any exception during verification means invalid JWT
            // This ensures consistent timing regardless of failure type
            return false;
        }
    }

    /// <summary>
    /// Extracts the payload from a JWT without verifying the signature
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <returns>Decoded payload JSON string</returns>
    /// <remarks>
    /// WARNING: This does not verify the signature. Always call VerifySignedJwt before trusting the payload.
    /// </remarks>
    public static string ExtractPayload(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);

        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format", nameof(jwt));
        }

        return Base64UrlEncoder.DecodeString(parts[1]);
    }

    /// <summary>
    /// Extracts the header from a JWT without verifying the signature
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <returns>Decoded header JSON string</returns>
    /// <remarks>
    /// WARNING: This does not verify the signature. Always call VerifySignedJwt before trusting the header.
    /// </remarks>
    public static string ExtractHeader(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);

        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format", nameof(jwt));
        }

        return Base64UrlEncoder.DecodeString(parts[0]);
    }
}
