using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Bounded offline publication and exact comparison of a two-key did:web
/// overlap document. Both Ed25519 keys and the DID must already be approved
/// by the caller. This never enrolls, rotates or promotes issuer trust.
/// </summary>
public static class DidWebPinnedKeyTransition
{
    private const int MaximumDocumentCharacters = 16_384;

    /// <summary>
    /// Prepare a DID Core document with two distinct Ed25519 verification
    /// methods. Both keys are explicitly active for authentication and
    /// assertion during the publication overlap period.
    /// </summary>
    /// <remarks>
    /// The operator separately controls publication, private keys and the
    /// decision to retire an old method. Public bytes do not prove custody.
    /// </remarks>
    public static string CreateTransitionDocument(
        string didIdentifier, byte[] oldPublicKey, byte[] newPublicKey)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(oldPublicKey);
        ArgumentNullException.ThrowIfNull(newPublicKey);

        if (!new DidWebMethod().IsValid(didIdentifier))
        {
            throw new ArgumentException(
                "A supported, canonical did:web DID is required.",
                nameof(didIdentifier));
        }

        if (oldPublicKey.Length != 32)
        {
            throw new ArgumentException(
                "The old Ed25519 public key must be 32 bytes.",
                nameof(oldPublicKey));
        }

        if (newPublicKey.Length != 32 ||
            CryptographicOperations.FixedTimeEquals(oldPublicKey, newPublicKey))
        {
            throw new ArgumentException(
                "The successor must be a distinct 32-byte Ed25519 public key.",
                nameof(newPublicKey));
        }

        string first = didIdentifier + "#key-1";
        string second = didIdentifier + "#key-2";
        string oldMultibase = new DidKeyMethod().GenerateDidIdentifier(
            oldPublicKey)["did:key:".Length..];
        string newMultibase = new DidKeyMethod().GenerateDidIdentifier(
            newPublicKey)["did:key:".Length..];

        var document = new Dictionary<string, object>
        {
            ["@context"] = new[]
            {
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            ["id"] = didIdentifier,
            ["verificationMethod"] = new[]
            {
                new Dictionary<string, string>
                {
                    ["id"] = first,
                    ["type"] = "Ed25519VerificationKey2020",
                    ["controller"] = didIdentifier,
                    ["publicKeyMultibase"] = oldMultibase
                },
                new Dictionary<string, string>
                {
                    ["id"] = second,
                    ["type"] = "Ed25519VerificationKey2020",
                    ["controller"] = didIdentifier,
                    ["publicKeyMultibase"] = newMultibase
                }
            },
            ["authentication"] = new[] { first, second },
            ["assertionMethod"] = new[] { first, second }
        };

        return JsonSerializer.Serialize(document);
    }

    /// <summary>
    /// Verify a retrieved two-key overlap document against the DID and both
    /// exact, independently pre-enrolled public keys. JSON object property
    /// ordering and whitespace are irrelevant; arrays retain their meaning.
    /// </summary>
    /// <remarks>
    /// This checks the supplied bytes only. It does not retrieve or host the
    /// document, prove DNS ownership or private-key possession, automatically
    /// trust a successor, or authorize an Agent or business transaction.
    /// </remarks>
    public static bool MatchesExpectedTransitionDocument(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedNewPublicKey, string publishedDocumentJson)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedNewPublicKey);
        ArgumentNullException.ThrowIfNull(publishedDocumentJson);

        if (!new DidWebMethod().IsValid(didIdentifier) ||
            pinnedOldPublicKey.Length != 32 ||
            pinnedNewPublicKey.Length != 32 ||
            CryptographicOperations.FixedTimeEquals(
                pinnedOldPublicKey, pinnedNewPublicKey) ||
            publishedDocumentJson.Length is 0 or > MaximumDocumentCharacters)
        {
            return false;
        }

        try
        {
            string expectedJson = CreateTransitionDocument(
                didIdentifier, pinnedOldPublicKey, pinnedNewPublicKey);
            using JsonDocument expected = JsonDocument.Parse(expectedJson);
            using JsonDocument actual = JsonDocument.Parse(
                publishedDocumentJson,
                new JsonDocumentOptions
                {
                    MaxDepth = 8,
                    CommentHandling = JsonCommentHandling.Disallow,
                    AllowTrailingCommas = false
                });

            return MatchesExactly(actual.RootElement, expected.RootElement);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            // JsonDocument can defer malformed Unicode escape decoding until
            // GetString() or JsonProperty.Name is accessed.
            return false;
        }
    }

    internal static bool MatchesExactly(JsonElement actual, JsonElement expected)
    {
        if (actual.ValueKind != expected.ValueKind)
        {
            return false;
        }

        switch (actual.ValueKind)
        {
            case JsonValueKind.Object:
                var names = new HashSet<string>(StringComparer.Ordinal);
                int count = 0;
                foreach (JsonProperty property in actual.EnumerateObject())
                {
                    if (!names.Add(property.Name) ||
                        !expected.TryGetProperty(property.Name,
                            out JsonElement expectedValue) ||
                        !MatchesExactly(property.Value, expectedValue))
                    {
                        return false;
                    }

                    count++;
                }

                return count == expected.EnumerateObject().Count();

            case JsonValueKind.Array:
                if (actual.GetArrayLength() != expected.GetArrayLength())
                {
                    return false;
                }

                for (int i = 0; i < expected.GetArrayLength(); i++)
                {
                    if (!MatchesExactly(actual[i], expected[i]))
                    {
                        return false;
                    }
                }

                return true;

            case JsonValueKind.String:
                return string.Equals(actual.GetString(), expected.GetString(),
                    StringComparison.Ordinal);

            default:
                // The restricted DID document contains only strings, arrays
                // and objects. Reject null/boolean/number substitutions.
                return false;
        }
    }
}
