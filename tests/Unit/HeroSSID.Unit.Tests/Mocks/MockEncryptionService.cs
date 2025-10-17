namespace HeroSSID.Unit.Tests.Mocks;

/// <summary>
/// Mock encryption service for unit testing
/// Uses simple XOR encryption (NOT secure - for testing only)
/// </summary>
internal static class MockEncryptionService
{
    private const byte XOR_KEY = 0x42; // Simple XOR key for mock encryption

    /// <summary>
    /// Mock encrypts data using XOR (deterministic for testing)
    /// </summary>
    public static Task<byte[]> EncryptPrivateKeyAsync(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var encrypted = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
        {
            encrypted[i] = (byte)(plaintext[i] ^ XOR_KEY);
        }

        return Task.FromResult(encrypted);
    }

    /// <summary>
    /// Mock decrypts data using XOR (deterministic for testing)
    /// </summary>
    public static Task<byte[]> DecryptPrivateKeyAsync(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        // XOR encryption is symmetric, so decrypt is same as encrypt
        var decrypted = new byte[ciphertext.Length];
        for (int i = 0; i < ciphertext.Length; i++)
        {
            decrypted[i] = (byte)(ciphertext[i] ^ XOR_KEY);
        }

        return Task.FromResult(decrypted);
    }

    /// <summary>
    /// Verifies that encryption/decryption is working correctly
    /// </summary>
    public static async Task<bool> VerifyRoundTripAsync(byte[] original)
    {
        var encrypted = await EncryptPrivateKeyAsync(original).ConfigureAwait(false);
        var decrypted = await DecryptPrivateKeyAsync(encrypted).ConfigureAwait(false);

        if (original.Length != decrypted.Length)
        {
            return false;
        }

        for (int i = 0; i < original.Length; i++)
        {
            if (original[i] != decrypted[i])
            {
                return false;
            }
        }

        return true;
    }
}
