using System.Text.Json;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Checks an externally retrieved did:web document against an independently
/// pinned DID and Ed25519 public key. This does not fetch HTTPS content, prove
/// domain ownership, authorize a party, or enroll an issuer as trusted.
/// </summary>
/// <remarks>
/// This deliberately accepts only the one-key, two-purpose document profile
/// emitted by <see cref="DidWebMethod.CreateDidDocument"/>. Other valid
/// did:web documents, including rotated and multi-key documents, can fail.
/// A caller must fetch from <see cref="DidWebMethod.GetDocumentUri"/> using its
/// own safe transport and pin both the requested DID and expected key.
/// </remarks>
public static class DidWebPublishedKeyMatch
{
    private const int MaximumDocumentCharacters = 16_384;

    private static readonly string[] s_documentFields =
        ["@context", "id", "verificationMethod", "authentication", "assertionMethod"];

    private static readonly string[] s_verificationFields =
        ["id", "type", "controller", "publicKeyMultibase"];

    private static readonly string[] s_contextValues =
        ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"];

    /// <summary>
    /// Returns true if the retrieved JSON exactly matches the expected
    /// restricted single-Ed25519-key DID document profile, independent of
    /// whitespace or JSON property ordering.
    /// </summary>
    /// <remarks>
    /// Matching proves only that the supplied JSON contains the pre-pinned
    /// key for the stated DID. It does not prove where the bytes came from,
    /// establish control of the private key, identity, issuer trust or consent.
    /// </remarks>
    public static bool MatchesExpectedDocument(
        string didIdentifier, byte[] expectedPublicKey, string retrievedDocumentJson)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(expectedPublicKey);
        ArgumentNullException.ThrowIfNull(retrievedDocumentJson);

        if (expectedPublicKey.Length != 32 ||
            retrievedDocumentJson.Length is 0 or > MaximumDocumentCharacters ||
            !new DidWebMethod().IsValid(didIdentifier))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                retrievedDocumentJson,
                new JsonDocumentOptions
                {
                    MaxDepth = 8,
                    CommentHandling = JsonCommentHandling.Disallow,
                    AllowTrailingCommas = false
                });

            JsonElement root = document.RootElement;
            if (!HasExactlyTheseFields(root, s_documentFields) ||
                !MatchesString(root, "id", didIdentifier) ||
                !MatchesStringArray(root, "@context", s_contextValues))
            {
                return false;
            }

            string verificationId = didIdentifier + "#key-1";
            if (!root.TryGetProperty("verificationMethod", out JsonElement methods) ||
                methods.ValueKind != JsonValueKind.Array || methods.GetArrayLength() != 1 ||
                !MatchesStringArray(root, "authentication", [verificationId]) ||
                !MatchesStringArray(root, "assertionMethod", [verificationId]))
            {
                return false;
            }

            JsonElement method = methods[0];
            if (!HasExactlyTheseFields(method, s_verificationFields) ||
                !MatchesString(method, "id", verificationId) ||
                !MatchesString(method, "controller", didIdentifier) ||
                !MatchesString(method, "type", "Ed25519VerificationKey2020"))
            {
                return false;
            }

            // Same DID + a substituted Ed25519 key is NOT a valid pinned match.
            // did:web is location-based rather than derived from the key.
            string didKey = new DidKeyMethod().GenerateDidIdentifier(expectedPublicKey);
            string expectedMultibase = didKey["did:key:".Length..];
            return MatchesString(method, "publicKeyMultibase", expectedMultibase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasExactlyTheseFields(JsonElement element, string[] fields)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        // Reject duplicate properties, even when the duplicated value matches.
        // GetProperty() alone would take the last value and mask ambiguity.
        int present = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            int index = Array.IndexOf(fields, property.Name);
            if (index < 0 || (present & (1 << index)) != 0)
            {
                return false;
            }

            present |= 1 << index;
        }

        return present == (1 << fields.Length) - 1;
    }

    private static bool MatchesString(JsonElement element, string name, string expected) =>
        element.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String &&
        string.Equals(value.GetString(), expected, StringComparison.Ordinal);

    private static bool MatchesStringArray(JsonElement element, string name, string[] expected)
    {
        if (!element.TryGetProperty(name, out JsonElement values) ||
            values.ValueKind != JsonValueKind.Array ||
            values.GetArrayLength() != expected.Length)
        {
            return false;
        }

        for (int i = 0; i < expected.Length; i++)
        {
            JsonElement value = values[i];
            if (value.ValueKind != JsonValueKind.String ||
                !string.Equals(value.GetString(), expected[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}
