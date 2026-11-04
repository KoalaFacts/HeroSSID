using System.Text.Json;
using System.Text.Json.Serialization;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.DidOperations.Models;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Bounded offline did:web DID Document preparation for a domain the caller
/// independently controls. No DNS/HTTPS lookup, domain ownership verification,
/// key hosting, remote resolution or issuer trust enrollment is performed.
/// This deliberately supports only DNS names and simple ASCII path segments;
/// a full did:web resolver must implement the broader method specification.
/// </summary>
public sealed class DidWebMethod : IDidMethod
{
    private const string Prefix = "did:web:";
    private const int MaximumDidLength = 512;
    private const int MaximumPathSegments = 8;
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <inheritdoc />
    public string MethodName => "web";

    /// <summary>
    /// Build a did:web identifier from explicitly configured options:
    /// "domain" is a lowercase ASCII DNS name with at least two labels;
    /// optional "path" is slash-delimited safe ASCII segments. The DID is
    /// location-based, not derived from the key as a did:key would be.
    /// </summary>
    public string GenerateDidIdentifier(byte[] publicKey, Dictionary<string, object>? options = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey.Length != 32)
        {
            throw new ArgumentException("An Ed25519 public key must be 32 bytes.", nameof(publicKey));
        }

        if (options is null ||
            !options.TryGetValue("domain", out object? rawDomain) ||
            rawDomain is not string domain || !IsValidDomain(domain) ||
            options.Keys.Any(static name => name != "domain" && name != "path"))
        {
            throw new ArgumentException(
                "Provide a valid lowercase DNS domain and optional safe path.", nameof(options));
        }

        if (!options.TryGetValue("path", out object? rawPath))
        {
            return Prefix + domain;
        }

        if (rawPath is not string path)
        {
            throw new ArgumentException("Path must be a nonempty string.", nameof(options));
        }

        string[] segments = path.Split('/');
        if (segments.Length is < 1 or > MaximumPathSegments ||
            segments.Any(static segment => !IsValidPathSegment(segment)))
        {
            throw new ArgumentException(
                "Path must contain only bounded, nonempty ASCII segments.", nameof(options));
        }

        string did = Prefix + domain + ":" + string.Join(":", segments);
        if (!IsValid(did))
        {
            throw new ArgumentException("The resulting did:web is too long.", nameof(options));
        }

        return did;
    }

    /// <summary>
    /// Generate a standalone DID Core JSON-LD document to publish at the URL
    /// from <see cref="GetDocumentUri"/>. This is not a signed proof of hosting
    /// authority. The caller must verify its own key custody and HTTPS domain
    /// control, publish the exact document, and test external resolution.
    /// </summary>
    public string CreateDidDocument(string didIdentifier, byte[] publicKey,
        Dictionary<string, object>? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey.Length != 32)
        {
            throw new ArgumentException("An Ed25519 public key must be 32 bytes.", nameof(publicKey));
        }

        if (!IsValid(didIdentifier))
        {
            throw new ArgumentException("Invalid or unsupported did:web identifier.", nameof(didIdentifier));
        }

        if (options is not null &&
            !string.Equals(GenerateDidIdentifier(publicKey, options), didIdentifier,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The configured domain/path do not match the DID document id.", nameof(options));
        }

        // Reuse the verified did:key Ed25519 multicodec encoder. The key is
        // placed in a did:web verification method, without implying the domain
        // has actually been published or the DID has been externally resolved.
        string didKey = new DidKeyMethod().GenerateDidIdentifier(publicKey);
        string multibaseKey = didKey.Substring("did:key:".Length);
        string verificationMethodId = didIdentifier + "#key-1";
        var document = new DidDocument
        {
            Context =
            [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            Id = didIdentifier,
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Ed25519VerificationKey2020",
                    Controller = didIdentifier,
                    PublicKeyMultibase = multibaseKey
                }
            ],
            Authentication = [verificationMethodId],
            AssertionMethod = [verificationMethodId]
        };

        return JsonSerializer.Serialize(document, s_jsonOptions);
    }

    /// <summary>
    /// Compute the exact standard HTTPS publication location without making a
    /// request: domain-only DIDs use /.well-known/did.json; a path DID uses
    /// /{path}/did.json. Only the restricted profile accepted here is allowed.
    /// </summary>
    public static Uri GetDocumentUri(string didIdentifier)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        if (!IsValidIdentifier(didIdentifier))
        {
            throw new ArgumentException("Invalid or unsupported did:web identifier.", nameof(didIdentifier));
        }

        string[] parts = didIdentifier.Substring(Prefix.Length).Split(':');
        string path = parts.Length == 1
            ? "/.well-known/did.json"
            : "/" + string.Join("/", parts.Skip(1)) + "/did.json";
        return new Uri("https://" + parts[0] + path, UriKind.Absolute);
    }

    /// <inheritdoc />
    public bool CanHandle(string did) =>
        did?.StartsWith(Prefix, StringComparison.Ordinal) == true;

    /// <inheritdoc />
    public bool IsValid(string did) => IsValidIdentifier(did);

    private static bool IsValidIdentifier(string? did)
    {
        if (did is null || did.Length > MaximumDidLength ||
            !did.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = did.Substring(Prefix.Length).Split(':');
        return parts.Length is >= 1 and <= MaximumPathSegments + 1 &&
            IsValidDomain(parts[0]) &&
            parts.Skip(1).All(static segment => IsValidPathSegment(segment));
    }

    private static bool IsValidDomain(string domain)
    {
        if (domain.Length is < 4 or > 253)
        {
            return false;
        }

        string[] labels = domain.Split('.');
        if (labels.Length < 2 || !labels[^1].Any(static letter => letter is >= 'a' and <= 'z'))
        {
            return false;
        }

        foreach (string label in labels)
        {
            if (label.Length is < 1 or > 63 ||
                !IsAsciiLowerAlphanumeric(label[0]) ||
                !IsAsciiLowerAlphanumeric(label[^1]) ||
                !label.All(static letter => IsAsciiLowerAlphanumeric(letter) || letter == '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiLowerAlphanumeric(char character) =>
        character is >= 'a' and <= 'z' or >= '0' and <= '9';

    private static bool IsValidPathSegment(string segment) =>
        segment.Length is >= 1 and <= 64 &&
        segment.All(static character => char.IsAsciiLetterOrDigit(character) ||
            character is '-' or '_');
}
