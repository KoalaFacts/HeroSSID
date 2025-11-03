namespace HeroSSID.Infrastructure.KeyEncryption;

/// <summary>
/// Service for encrypting and decrypting sensitive key material
/// MVP: Uses .NET Data Protection API
/// v2: Will be replaced with Azure Key Vault integration
/// </summary>
public interface IKeyEncryptionService
{
    /// <summary>
    /// Encrypts sensitive data (e.g., private keys)
    /// </summary>
    /// <param name="plaintext">Data to encrypt</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(byte[] plaintext);

    /// <summary>
    /// Decrypts previously encrypted data
    /// </summary>
    /// <param name="ciphertext">Encrypted data</param>
    /// <returns>Decrypted plaintext</returns>
    public byte[] Decrypt(byte[] ciphertext);

    /// <summary>
    /// Encrypts sensitive string data
    /// </summary>
    /// <param name="plaintext">String to encrypt</param>
    /// <returns>Base64-encoded encrypted data</returns>
    public string EncryptString(string plaintext);

    /// <summary>
    /// Decrypts previously encrypted string data
    /// </summary>
    /// <param name="ciphertext">Base64-encoded encrypted data</param>
    /// <returns>Decrypted string</returns>
    public string DecryptString(string ciphertext);
}
