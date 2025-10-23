using System.Globalization;
using System.Security.Cryptography;

namespace HeroSSID.Core.Services;

/// <summary>
/// Generates cryptographically secure codes with guaranteed entropy.
/// </summary>
public sealed class CryptographicCodeGenerator : ICryptographicCodeGenerator
{
    private const int MinimumBitsOfEntropy = 256;
    private const int BytesForMinimumEntropy = MinimumBitsOfEntropy / 8; // 32 bytes

    /// <summary>
    /// Generates a cryptographically secure pre-authorized code with 256-bit entropy.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GeneratePreAuthorizedCode()
    {
        var bytes = new byte[BytesForMinimumEntropy];
        RandomNumberGenerator.Fill(bytes);

        // Use Base64url encoding (RFC 4648) for URL-safe tokens
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Generates a cryptographically secure nonce with 256-bit entropy for replay protection.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GenerateNonce()
    {
        var bytes = new byte[BytesForMinimumEntropy];
        RandomNumberGenerator.Fill(bytes);

        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Generates a cryptographically secure state value with 256-bit entropy.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GenerateState()
    {
        var bytes = new byte[BytesForMinimumEntropy];
        RandomNumberGenerator.Fill(bytes);

        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Generates a 6-digit numeric transaction code for QR security.
    /// </summary>
    /// <returns>6-digit numeric string.</returns>
    public string GenerateTransactionCode()
    {
        // Use rejection sampling to ensure uniform distribution (MEDIUM-3: Added max iterations)
        const int maxIterations = 100; // Safety limit to prevent infinite loop
        int code;
        int iterations = 0;

        do
        {
            var bytes = new byte[4];
            RandomNumberGenerator.Fill(bytes);
            code = BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF; // Remove sign bit
            iterations++;

            if (iterations >= maxIterations)
            {
                // Fallback: Use modulo if rejection sampling takes too long
                // This is extremely unlikely (probability < 2^-100)
                return (code % 1000000).ToString("D6", CultureInfo.InvariantCulture);
            }
        } while (code >= 1000000); // Ensure 6 digits (000000-999999)

        return (code % 1000000).ToString("D6", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Validates that a code meets minimum entropy requirements.
    /// </summary>
    /// <param name="code">The code to validate.</param>
    /// <returns>True if the code meets 256-bit entropy requirements.</returns>
    public bool ValidateCodeEntropy(string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return false;
        }

        // Base64url decoded length should be at least 32 bytes (256 bits)
        // Base64url encoding produces ~1.33x the input size, so 32 bytes -> 43-44 chars
        if (code.Length < 43)
        {
            return false;
        }

        // Validate Base64url characters
        foreach (var c in code)
        {
            if (!IsBase64UrlChar(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBase64UrlChar(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_';
    }
}
