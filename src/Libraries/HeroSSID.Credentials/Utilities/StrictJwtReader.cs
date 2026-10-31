using System.Text.Json;

namespace HeroSSID.Credentials.Utilities;

/// <summary>Bounded, unambiguous JWT parsing. Parsing does not authenticate claims.</summary>
internal static class StrictJwtReader
{
    public static bool IsCanonicalCompact(string token, int maximumLength)
    {
        if (string.IsNullOrEmpty(token) || token.Length > maximumLength)
        {
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        try
        {
            foreach (var part in parts)
            {
                if (part.Length == 0 || !string.Equals(Base64UrlEncoder.Encode(Base64UrlEncoder.DecodeBytes(part)), part, StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return Base64UrlEncoder.DecodeBytes(parts[2]).Length == 64;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool TryRead(string token, string expectedType, int maximumLength, out JsonElement payload,
        string? expectedKeyId = null, string? expectedContentType = null)
    {
        payload = default;
        if (!IsCanonicalCompact(token, maximumLength))
        {
            return false;
        }

        try
        {
            var parts = token.Split('.');
            var options = new JsonDocumentOptions { MaxDepth = 16 };
            using var headerDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[0]), options);
            var header = headerDocument.RootElement;
            if (header.ValueKind != JsonValueKind.Object || !HasUniqueProperties(header))
            {
                return false;
            }

            // W3C VC-JOSE-COSE 2026 recommends cty=vc/vp, but older valid
            // direct JWTs may omit it. Never silently accept an incorrect or
            // unexpected content type or an extra JOSE header parameter.
            bool hasContentType = header.TryGetProperty("cty", out var contentType);
            if (header.EnumerateObject().Count() !=
                    (expectedKeyId is null ? 2 : 3) + (hasContentType ? 1 : 0) ||
                (hasContentType && (expectedContentType is null ||
                    contentType.ValueKind != JsonValueKind.String ||
                    !string.Equals(contentType.GetString(), expectedContentType, StringComparison.Ordinal))) ||
                !TryGetString(header, "alg", out var algorithm) || algorithm != "EdDSA" ||
                !TryGetString(header, "typ", out var type) || type != expectedType ||
                (expectedKeyId is not null && (!TryGetString(header, "kid", out var keyId) ||
                    !string.Equals(keyId, expectedKeyId, StringComparison.Ordinal))))
            {
                return false;
            }

            using var payloadDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]), options);
            if (payloadDocument.RootElement.ValueKind != JsonValueKind.Object || !HasUniqueProperties(payloadDocument.RootElement))
            {
                return false;
            }

            payload = payloadDocument.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            // JsonDocument defers decoding escaped strings; malformed UTF-8/UTF-16 must also fail closed.
            return false;
        }
    }

    public static bool TryGetString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()!;
        return !string.IsNullOrWhiteSpace(value);
    }

    public static bool TryGetTimestamp(JsonElement element, string name, out long value)
    {
        value = 0;
        return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number &&
            property.TryGetInt64(out value) && value >= 0 && value < 253402300800;
    }


    /// <summary>
    /// These strict, URI-pinned VC profiles do not expand JSON-LD contexts.
    /// A local context in any descendant object or array could redefine the
    /// meaning of a claim without changing the pinned top-level vocabulary.
    /// Reject such subjects rather than disclose potentially shadowed claims.
    /// </summary>
    public static bool HasEmbeddedContext(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (property.NameEquals("@context") ||
                    HasEmbeddedContext(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (HasEmbeddedContext(item))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool HasUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || !HasUniqueProperties(property.Value))
                {
                    return false;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (!HasUniqueProperties(item))
                {
                    return false;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.String)
        {
            // Validate every nested string now, before any untrusted value can escape the parser.
            _ = element.GetString();
        }

        return true;
    }
}
