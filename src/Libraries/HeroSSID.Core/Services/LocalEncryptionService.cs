using Microsoft.AspNetCore.DataProtection;

namespace HeroSSID.Core.Services;

/// <summary>
/// Local encryption service using .NET Data Protection API
/// </summary>
public sealed class LocalEncryptionService : IEncryptionService
{
    private readonly IDataProtector _protector;

    public LocalEncryptionService(IDataProtectionProvider dataProtectionProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);

        // Create a dedicated protector for HeroSSID private keys
        _protector = dataProtectionProvider.CreateProtector("HeroSSID.PrivateKeys.v1");
    }

    /// <summary>
    /// Encrypt plaintext data using Data Protection API
    /// </summary>
    public Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var ciphertext = _protector.Protect(plaintext);
            return Task.FromResult(ciphertext);
        }
        catch (Exception ex)
        {
            throw new EncryptionException("Failed to encrypt data", ex);
        }
    }

    /// <summary>
    /// Decrypt ciphertext data using Data Protection API
    /// </summary>
    public Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var plaintext = _protector.Unprotect(ciphertext);
            return Task.FromResult(plaintext);
        }
        catch (Exception ex)
        {
            throw new EncryptionException("Failed to decrypt data", ex);
        }
    }
}

/// <summary>
/// Exception thrown when encryption/decryption operations fail
/// </summary>
public sealed class EncryptionException : Exception
{
    public EncryptionException()
    {
    }

    public EncryptionException(string message)
        : base(message)
    {
    }

    public EncryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
