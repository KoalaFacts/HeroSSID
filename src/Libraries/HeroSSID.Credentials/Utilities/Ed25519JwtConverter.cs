using HeroSSID.Credentials.Crypto;
using Microsoft.IdentityModel.Tokens;
using NSec.Cryptography;
using System.Security.Cryptography;

namespace HeroSSID.Credentials.Utilities;

/// <summary>
/// Utility for converting Ed25519 keys to JWT-compatible security key formats.
/// Uses NSec.Cryptography (already a dependency for DID operations) and .NET 9 built-in APIs.
/// </summary>
public static class Ed25519JwtConverter
{
    private const int Ed25519PublicKeySize = 32;
    private const int Ed25519PrivateKeySize = 32;

    /// <summary>
    /// Converts a raw Ed25519 public key (32 bytes) to a SecurityKey for JWT verification
    /// </summary>
    /// <param name="publicKeyRaw">Raw Ed25519 public key bytes (32 bytes)</param>
    /// <returns>Ed25519SecurityKey for JWT signature verification</returns>
    /// <exception cref="ArgumentNullException">Thrown when publicKeyRaw is null</exception>
    /// <exception cref="ArgumentException">Thrown when publicKeyRaw has invalid length</exception>
    public static Ed25519SecurityKey ConvertToSecurityKey(byte[] publicKeyRaw)
    {
        ArgumentNullException.ThrowIfNull(publicKeyRaw);

        if (publicKeyRaw.Length == 0)
        {
            throw new ArgumentException("Public key cannot be empty", nameof(publicKeyRaw));
        }

        if (publicKeyRaw.Length != Ed25519PublicKeySize)
        {
            throw new ArgumentException(
                $"Ed25519 public key must be exactly {Ed25519PublicKeySize} bytes, got {publicKeyRaw.Length} bytes",
                nameof(publicKeyRaw));
        }

        // Create Ed25519 security key from raw public key
        var securityKey = new Ed25519SecurityKey(publicKeyRaw)
        {
            // Generate unique key ID (timestamp + random component for uniqueness)
            KeyId = $"ed25519-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}-{Guid.NewGuid():N}"
        };

        return securityKey;
    }

    /// <summary>
    /// Converts a raw Ed25519 private key (32 bytes) to SigningCredentials for JWT signing
    /// </summary>
    /// <param name="privateKeyRaw">Raw Ed25519 private key bytes (32 bytes, seed format)</param>
    /// <returns>SigningCredentials for JWT signature creation</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKeyRaw is null</exception>
    /// <exception cref="ArgumentException">Thrown when privateKeyRaw has invalid length</exception>
    /// <remarks>
    /// SECURITY: This method temporarily holds private key material in memory.
    /// The caller is responsible for securely clearing the input byte array after use.
    /// </remarks>
    public static SigningCredentials ConvertToSigningCredentials(byte[] privateKeyRaw)
    {
        ArgumentNullException.ThrowIfNull(privateKeyRaw);

        if (privateKeyRaw.Length == 0)
        {
            throw new ArgumentException("Private key cannot be empty", nameof(privateKeyRaw));
        }

        if (privateKeyRaw.Length != Ed25519PrivateKeySize)
        {
            throw new ArgumentException(
                $"Ed25519 private key must be exactly {Ed25519PrivateKeySize} bytes, got {privateKeyRaw.Length} bytes",
                nameof(privateKeyRaw));
        }

        // SECURITY: Temporary buffers for key material
        byte[]? publicKeyRaw = null;

        try
        {
            // Derive public key from private key seed using NSec.Cryptography
            var algorithm = SignatureAlgorithm.Ed25519;
            var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

            using var key = Key.Import(algorithm, privateKeyRaw, KeyBlobFormat.RawPrivateKey, keyParams);
            publicKeyRaw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            // Create Ed25519 security key with both private and public components
            var securityKey = new Ed25519SecurityKey(publicKeyRaw, privateKeyRaw)
            {
                KeyId = $"ed25519-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}-{Guid.NewGuid():N}"
            };

            return new SigningCredentials(securityKey, "EdDSA");
        }
        finally
        {
            // SECURITY: Clear temporary public key from memory using SecureZeroMemory pattern
            if (publicKeyRaw != null)
            {
                CryptographicOperations.ZeroMemory(publicKeyRaw);
            }
        }
    }
}
