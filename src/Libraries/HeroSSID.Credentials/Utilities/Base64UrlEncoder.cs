using System;
using System.Text;

namespace HeroSSID.Credentials.Utilities;

/// <summary>
/// Utility for Base64Url encoding/decoding (RFC 4648 Section 5)
/// Used for JWT header/payload/signature encoding
/// </summary>
public static class Base64UrlEncoder
{
    /// <summary>
    /// Encodes a byte array to Base64Url format
    /// </summary>
    /// <param name="input">Bytes to encode</param>
    /// <returns>Base64Url encoded string</returns>
    public static string Encode(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Standard base64 encoding
        var base64 = Convert.ToBase64String(input);

        // Convert to Base64Url: replace + with -, / with _, and remove padding =
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Encodes a UTF-8 string to Base64Url format
    /// </summary>
    /// <param name="input">String to encode</param>
    /// <returns>Base64Url encoded string</returns>
    public static string Encode(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var bytes = Encoding.UTF8.GetBytes(input);
        return Encode(bytes);
    }

    /// <summary>
    /// Decodes a Base64Url string to byte array
    /// </summary>
    /// <param name="input">Base64Url encoded string</param>
    /// <returns>Decoded bytes</returns>
    public static byte[] DecodeBytes(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Convert Base64Url to standard base64
        var base64 = input
            .Replace('-', '+')
            .Replace('_', '/');

        // Add padding if needed
        var padding = (4 - (base64.Length % 4)) % 4;
        if (padding > 0)
        {
            base64 += new string('=', padding);
        }

        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Decodes a Base64Url string to UTF-8 string
    /// </summary>
    /// <param name="input">Base64Url encoded string</param>
    /// <returns>Decoded string</returns>
    public static string DecodeString(string input)
    {
        var bytes = DecodeBytes(input);
        return Encoding.UTF8.GetString(bytes);
    }
}
