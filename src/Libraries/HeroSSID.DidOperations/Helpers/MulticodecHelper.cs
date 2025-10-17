namespace HeroSSID.DidOperations.Helpers;

/// <summary>
/// Provides methods for encoding and decoding Ed25519 public keys with multicodec prefixes.
/// According to the multicodec table, Ed25519 public keys use the 0xed01 prefix.
/// </summary>
public static class MulticodecHelper
{
    private const byte Ed25519PrefixByte1 = 0xed;
    private const byte Ed25519PrefixByte2 = 0x01;
    private const int Ed25519PublicKeyLength = 32;
    private const int Ed25519MulticodecLength = 34;

    /// <summary>
    /// Adds the Ed25519 multicodec prefix (0xed01) to a public key.
    /// </summary>
    /// <param name="publicKey">The 32-byte Ed25519 public key</param>
    /// <returns>A 34-byte array with the multicodec prefix</returns>
    /// <exception cref="ArgumentNullException">Thrown when publicKey is null</exception>
    /// <exception cref="ArgumentException">Thrown when publicKey is not 32 bytes</exception>
    public static byte[] AddEd25519Prefix(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != Ed25519PublicKeyLength)
        {
            throw new ArgumentException(
                $"Ed25519 public key must be {Ed25519PublicKeyLength} bytes, but was {publicKey.Length} bytes.",
                nameof(publicKey));
        }

        var result = new byte[Ed25519MulticodecLength];
        result[0] = Ed25519PrefixByte1;
        result[1] = Ed25519PrefixByte2;
        Array.Copy(publicKey, 0, result, 2, Ed25519PublicKeyLength);

        return result;
    }

    /// <summary>
    /// Removes the Ed25519 multicodec prefix (0xed01) from a multicodec-encoded key.
    /// </summary>
    /// <param name="multicodecKey">The 34-byte multicodec-encoded key</param>
    /// <returns>The 32-byte Ed25519 public key</returns>
    /// <exception cref="ArgumentNullException">Thrown when multicodecKey is null</exception>
    /// <exception cref="ArgumentException">Thrown when multicodecKey is invalid</exception>
    public static byte[] RemoveEd25519Prefix(byte[] multicodecKey)
    {
        ArgumentNullException.ThrowIfNull(multicodecKey);

        if (multicodecKey.Length != Ed25519MulticodecLength)
        {
            throw new ArgumentException(
                $"Multicodec-encoded Ed25519 key must be {Ed25519MulticodecLength} bytes, but was {multicodecKey.Length} bytes.",
                nameof(multicodecKey));
        }

        if (multicodecKey[0] != Ed25519PrefixByte1 || multicodecKey[1] != Ed25519PrefixByte2)
        {
            throw new ArgumentException(
                $"Invalid Ed25519 multicodec prefix. Expected 0xed01, but got 0x{multicodecKey[0]:x2}{multicodecKey[1]:x2}.",
                nameof(multicodecKey));
        }

        var result = new byte[Ed25519PublicKeyLength];
        Array.Copy(multicodecKey, 2, result, 0, Ed25519PublicKeyLength);

        return result;
    }
}
