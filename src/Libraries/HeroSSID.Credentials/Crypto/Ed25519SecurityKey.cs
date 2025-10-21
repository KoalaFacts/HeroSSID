using Microsoft.IdentityModel.Tokens;

namespace HeroSSID.Credentials.Crypto;

/// <summary>
/// Security key implementation for Ed25519 cryptographic operations
/// Uses .NET 9 System.Security.Cryptography.Ed25519 (Microsoft-maintained)
/// </summary>
public sealed class Ed25519SecurityKey : AsymmetricSecurityKey
{
    private readonly byte[] _publicKey;
    private readonly byte[]? _privateKey;

    /// <summary>
    /// Creates an Ed25519 security key from public key bytes
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key</param>
    public Ed25519SecurityKey(byte[] publicKey)
        : this(publicKey, null)
    {
    }

    /// <summary>
    /// Creates an Ed25519 security key from public and private key bytes
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key</param>
    /// <param name="privateKey">32-byte Ed25519 private key (optional)</param>
    /// <remarks>
    /// SECURITY: This constructor makes defensive copies of the input arrays to prevent
    /// external modification of cryptographic key material.
    /// </remarks>
    public Ed25519SecurityKey(byte[] publicKey, byte[]? privateKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(publicKey));
        }

        if (privateKey != null && privateKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(privateKey));
        }

        // SECURITY: Defensive copy to prevent external modification
        _publicKey = (byte[])publicKey.Clone();
        _privateKey = privateKey != null ? (byte[])privateKey.Clone() : null;
    }

    /// <summary>
    /// Gets a copy of the Ed25519 public key bytes
    /// </summary>
    /// <returns>Defensive copy of the public key</returns>
    /// <remarks>
    /// SECURITY: Returns a defensive copy to prevent external modification of the key material.
    /// Callers should clear the returned array when done using CryptographicOperations.ZeroMemory().
    /// </remarks>
    public byte[] GetPublicKeyCopy() => (byte[])_publicKey.Clone();

    /// <summary>
    /// Gets a copy of the Ed25519 private key bytes (null if public-key-only)
    /// </summary>
    /// <returns>Defensive copy of the private key, or null if not present</returns>
    /// <remarks>
    /// SECURITY: Returns a defensive copy to prevent external modification of the key material.
    /// Callers MUST clear the returned array immediately after use using CryptographicOperations.ZeroMemory().
    /// </remarks>
    public byte[]? GetPrivateKeyCopy() => _privateKey != null ? (byte[])_privateKey.Clone() : null;

    /// <summary>
    /// Gets the Ed25519 public key bytes (for backward compatibility - DEPRECATED)
    /// </summary>
    /// <remarks>
    /// DEPRECATED: Use GetPublicKeyCopy() instead for better security.
    /// This property returns the internal array for backward compatibility but will be removed in a future version.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Backward compatibility - deprecated")]
    [Obsolete("Use GetPublicKeyCopy() instead to prevent external modification of key material")]
    public byte[] PublicKey => _publicKey;

    /// <summary>
    /// Gets the Ed25519 private key bytes (null if public-key-only) (for backward compatibility - DEPRECATED)
    /// </summary>
    /// <remarks>
    /// DEPRECATED: Use GetPrivateKeyCopy() instead for better security.
    /// This property returns the internal array for backward compatibility but will be removed in a future version.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Backward compatibility - deprecated")]
    [Obsolete("Use GetPrivateKeyCopy() instead to prevent external modification of key material")]
    public byte[]? PrivateKey => _privateKey;

    /// <summary>
    /// Indicates whether this key has a private key component
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Abstract property implementation")]
    [Obsolete("Use PrivateKeyStatus instead")]
    public override bool HasPrivateKey => _privateKey != null;

    /// <summary>
    /// Gets the private key status
    /// </summary>
    public override PrivateKeyStatus PrivateKeyStatus => _privateKey != null
        ? PrivateKeyStatus.Exists
        : PrivateKeyStatus.DoesNotExist;

    /// <summary>
    /// Key size in bits (Ed25519 is always 256 bits)
    /// </summary>
    public override int KeySize => 256;

    /// <summary>
    /// Security key algorithm (EdDSA)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Required by AsymmetricSecurityKey API")]
    public string Algorithm => "EdDSA";
}
