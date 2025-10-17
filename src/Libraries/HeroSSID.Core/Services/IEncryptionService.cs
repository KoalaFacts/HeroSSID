namespace HeroSSID.Core.Services;

/// <summary>
/// Service for encrypting and decrypting sensitive data (private keys)
/// </summary>
public interface IEncryptionService
{
    /// <summary>
    /// Encrypt plaintext data
    /// </summary>
    public Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypt ciphertext data
    /// </summary>
    public Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
}
