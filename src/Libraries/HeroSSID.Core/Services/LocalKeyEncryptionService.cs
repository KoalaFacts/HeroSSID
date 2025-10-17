using System.Text;
using HeroSSID.Core.Interfaces;
using Microsoft.AspNetCore.DataProtection;

namespace HeroSSID.Core.Services;

/// <summary>
/// Local file-based key encryption using .NET Data Protection API
/// For MVP single-machine deployment
/// v2: Replace with Azure Key Vault or HSM-based encryption
/// </summary>
public sealed class LocalKeyEncryptionService : IKeyEncryptionService
{
    private readonly IDataProtector _protector;

    public LocalKeyEncryptionService(IDataProtectionProvider dataProtectionProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        _protector = dataProtectionProvider.CreateProtector("HeroSSID.KeyProtection");
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext cannot be empty", nameof(plaintext));
        }

        return _protector.Protect(plaintext);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (ciphertext.Length == 0)
        {
            throw new ArgumentException("Ciphertext cannot be empty", nameof(ciphertext));
        }

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
