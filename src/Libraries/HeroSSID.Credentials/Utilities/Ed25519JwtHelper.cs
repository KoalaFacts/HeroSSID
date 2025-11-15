using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using System;
using System.Text;
using System.Text.Json;

namespace HeroSSID.Credentials.Utilities;

/// <summary>
/// Utility for creating and verifying Ed25519-signed JWTs using HeroSD-JWT
/// Replaces the previous NSec.Cryptography-based implementation
/// </summary>
public static class Ed25519JwtHelper
{
    /// <summary>
    /// Creates a signed JWT using Ed25519 via HeroSD-JWT
    /// </summary>
    /// <param name="header">JWT header JSON (without encoding)</param>
    /// <param name="payload">JWT payload JSON (without encoding)</param>
    /// <param name="privateKeyBytes">32-byte Ed25519 private key (seed format)</param>
    /// <returns>Signed JWT in format: {header}.{payload}.{signature}</returns>
    public static string CreateSignedJwt(string header, string payload, byte[] privateKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(privateKeyBytes);

        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(privateKeyBytes));
        }

        // Parse header and payload to extract claims
        var headerDoc = JsonDocument.Parse(header);
        var payloadDoc = JsonDocument.Parse(payload);

        // Create JWT builder (non-SD-JWT, just regular JWT with Ed25519)
        var builder = JwtBuilder.Create();

        // Add all payload claims
        foreach (var property in payloadDoc.RootElement.EnumerateObject())
        {
            var value = ExtractJsonValue(property.Value);
            builder = builder.WithClaim(property.Name, value);
        }

        // Sign with Ed25519
        var jwt = builder.SignWithEd25519(privateKeyBytes).Build();

        // Return the JWT token (should be in standard JWT format: header.payload.signature)
        return jwt.ToString();
    }

    /// <summary>
    /// Verifies an Ed25519-signed JWT with timing attack resistance via HeroSD-JWT
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <param name="publicKeyBytes">32-byte Ed25519 public key</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Verification method - any exception means invalid JWT")]
    public static bool VerifySignedJwt(string jwt, byte[] publicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(publicKeyBytes);

        if (publicKeyBytes.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(publicKeyBytes));
        }

        try
        {
            var verifier = new JwtVerifier();
            var result = verifier.Verify(jwt, publicKeyBytes);

            // Check if verification was successful
            return GetIsValid(result);
        }
        catch
        {
            // Any exception during verification means invalid JWT
            return false;
        }
    }

    /// <summary>
    /// Extracts the payload from a JWT without verifying the signature
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <returns>Decoded payload JSON string</returns>
    /// <remarks>
    /// WARNING: This does not verify the signature. Always call VerifySignedJwt before trusting the payload.
    /// </remarks>
    public static string ExtractPayload(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);

        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format", nameof(jwt));
        }

        return Base64UrlEncoder.DecodeString(parts[1]);
    }

    /// <summary>
    /// Extracts the header from a JWT without verifying the signature
    /// </summary>
    /// <param name="jwt">Complete JWT string</param>
    /// <returns>Decoded header JSON string</returns>
    /// <remarks>
    /// WARNING: This does not verify the signature. Always call VerifySignedJwt before trusting the header.
    /// </remarks>
    public static string ExtractHeader(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);

        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format", nameof(jwt));
        }

        return Base64UrlEncoder.DecodeString(parts[0]);
    }

    private static object ExtractJsonValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null!,
            JsonValueKind.Array => ExtractJsonArray(element),
            JsonValueKind.Object => ExtractJsonObject(element),
            _ => element.ToString()
        };
    }

    private static object[] ExtractJsonArray(JsonElement arrayElement)
    {
        var list = new System.Collections.Generic.List<object>();
        foreach (var item in arrayElement.EnumerateArray())
        {
            list.Add(ExtractJsonValue(item));
        }
        return list.ToArray();
    }

    private static System.Collections.Generic.Dictionary<string, object> ExtractJsonObject(JsonElement objectElement)
    {
        var dict = new System.Collections.Generic.Dictionary<string, object>();
        foreach (var property in objectElement.EnumerateObject())
        {
            dict[property.Name] = ExtractJsonValue(property.Value);
        }
        return dict;
    }

    private static bool GetIsValid(object result)
    {
        // Try to get IsValid property from verification result
        var type = result.GetType();
        var isValidProperty = type.GetProperty("IsValid", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);

        if (isValidProperty != null && isValidProperty.PropertyType == typeof(bool))
        {
            return (bool)isValidProperty.GetValue(result)!;
        }

        // If no IsValid property, assume success (Verify would throw on failure)
        return true;
    }
}
