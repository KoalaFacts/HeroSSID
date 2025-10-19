using System.Text;
using HeroSSID.Core.Interfaces;
using Microsoft.AspNetCore.DataProtection;

namespace HeroSSID.Core.Services;

/// <summary>
/// Local file-based key encryption using .NET Data Protection API
/// For MVP single-machine deployment
/// Supports key rotation via Data Protection's built-in versioning
/// v2: Replace with Azure Key Vault or HSM-based encryption
/// </summary>
/// <remarks>
/// SECURITY: This implementation uses ASP.NET Core Data Protection which provides:
/// - Automatic key rotation (default: 90 days)
/// - Key expiration and revocation support
/// - Backward compatibility for decryption of old keys
/// The purpose string creates an isolated key ring for HeroSSID operations.
/// </remarks>
public sealed class LocalKeyEncryptionService : IKeyEncryptionService
{
    private readonly IDataProtector _protector;

    /// <summary>
    /// Initializes the encryption service with automatic key rotation support
    /// </summary>
    /// <param name="dataProtectionProvider">Data Protection provider configured with key rotation</param>
    public LocalKeyEncryptionService(IDataProtectionProvider dataProtectionProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);

        // SECURITY: Using a specific purpose string isolates this key ring from others
        // Data Protection handles key rotation automatically based on configured lifetime
        _protector = dataProtectionProvider.CreateProtector("HeroSSID.KeyProtection");
    }

    /// <inheritdoc />
    /// <remarks>
    /// SECURITY: Uses the current active encryption key. Data Protection will:
    /// - Automatically select the newest non-expired key for encryption
    /// - Include key version metadata in the ciphertext
    /// - Support decryption of data encrypted with older keys
    /// </remarks>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext cannot be empty", nameof(plaintext));
        }

        // Data Protection automatically uses the current active key
        // and embeds version information for future decryption
        return _protector.Protect(plaintext);
    }

    /// <inheritdoc />
    /// <remarks>
    /// SECURITY: Automatically detects which key version was used for encryption
    /// and uses the corresponding key for decryption. Supports decryption of data
    /// encrypted with rotated (old) keys as long as they haven't been revoked.
    /// </remarks>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (ciphertext.Length == 0)
        {
            throw new ArgumentException("Ciphertext cannot be empty", nameof(ciphertext));
        }

        // Data Protection reads the embedded key version and uses the correct key
        return _protector.Unprotect(ciphertext);
    }

    /// <inheritdoc />
    public string EncryptString(string plaintext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var encryptedBytes = Encrypt(plaintextBytes);
        return Convert.ToBase64String(encryptedBytes);
    }

    /// <inheritdoc />
    public string DecryptString(string ciphertext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);

        var ciphertextBytes = Convert.FromBase64String(ciphertext);
        var decryptedBytes = Decrypt(ciphertextBytes);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
