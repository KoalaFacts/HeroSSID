namespace HeroSSID.DidOperations.DidSigning;

/// <summary>
/// Service for signing messages and verifying signatures using DID-associated keys.
/// Uses Ed25519 signature algorithm via NSec/libsodium.
/// </summary>
public interface IDidSigningService
{
    /// <summary>
    /// Signs a message using the private key associated with a DID.
    /// </summary>
    /// <param name="didIdentifier">The DID identifier whose private key will be used for signing</param>
    /// <param name="message">The message bytes to sign</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>64-byte Ed25519 signature</returns>
    /// <exception cref="ArgumentNullException">Thrown if didIdentifier or message is null</exception>
    /// <exception cref="InvalidOperationException">Thrown if DID not found or private key cannot be decrypted</exception>
    /// <exception cref="CryptographicException">Thrown if signing operation fails</exception>
    public Task<byte[]> SignAsync(string didIdentifier, byte[] message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a signature using the public key associated with a DID.
    /// </summary>
    /// <param name="didIdentifier">The DID identifier whose public key will be used for verification</param>
    /// <param name="message">The original message bytes that were signed</param>
    /// <param name="signature">The 64-byte Ed25519 signature to verify</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
    /// <exception cref="InvalidOperationException">Thrown if DID not found</exception>
    public Task<bool> VerifyAsync(string didIdentifier, byte[] message, byte[] signature, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a signature using a raw public key (not from database).
    /// Useful for verifying signatures from external DIDs.
    /// </summary>
    /// <param name="publicKey">The 32-byte Ed25519 public key</param>
    /// <param name="message">The original message bytes that were signed</param>
    /// <param name="signature">The 64-byte Ed25519 signature to verify</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
    /// <exception cref="ArgumentException">Thrown if publicKey is not 32 bytes or signature is not 64 bytes</exception>
    public bool VerifyWithPublicKey(byte[] publicKey, byte[] message, byte[] signature);
}
