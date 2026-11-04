using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Explicit finalisation of a did:web two-key publication overlap. The caller
/// must independently preapprove both original and successor Ed25519 keys.
/// Publication, private-key possession and issuer trust remain operator owned.
/// </summary>
public static class DidWebPinnedKeyRetirement
{
    private const int MaximumDocumentCharacters = 16_384;

    /// <summary>
    /// Construct the exact DID Core successor-only document after an operator
    /// has completed the two-key overlap. Preserve the successor's #key-2
    /// verification method id, remove #key-1, and remove every old-key
    /// authentication and assertion relationship.
    /// </summary>
    public static string CreateRetirementDocument(
        string didIdentifier, byte[] pinnedOldPublicKey, byte[] pinnedSuccessorPublicKey)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedSuccessorPublicKey);

        if (!new DidWebMethod().IsValid(didIdentifier))
        {
            throw new ArgumentException(
                "A supported canonical did:web DID is required.", nameof(didIdentifier));
        }

        if (pinnedOldPublicKey.Length != 32)
        {
            throw new ArgumentException(
                "The original Ed25519 public key must be 32 bytes.",
                nameof(pinnedOldPublicKey));
        }

        if (pinnedSuccessorPublicKey.Length != 32 ||
            CryptographicOperations.FixedTimeEquals(
                pinnedOldPublicKey, pinnedSuccessorPublicKey))
        {
            throw new ArgumentException(
                "The independently approved successor must be a distinct 32-byte Ed25519 key.",
                nameof(pinnedSuccessorPublicKey));
        }

        // Derive the successor method, context and controller from the exact
        // already-defined overlap profile instead of allocating a different
        // fragment (#key-1) to the successor after retirement.
        string overlap = DidWebPinnedKeyTransition.CreateTransitionDocument(
            didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey);
        JsonObject document = JsonNode.Parse(overlap)!.AsObject();
        JsonNode successor = document["verificationMethod"]![1]!.DeepClone();
        document["verificationMethod"] = new JsonArray(successor);
        document["authentication"] = new JsonArray(didIdentifier + "#key-2");
        document["assertionMethod"] = new JsonArray(didIdentifier + "#key-2");
        return document.ToJsonString();
    }

    /// <summary>
    /// Compare externally obtained content with the exact successor-only
    /// document for both independently pinned keys. A match does not establish
    /// who served the bytes, private-key custody, issuer trust or authority.
    /// </summary>
    public static bool MatchesExpectedRetirementDocument(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, string publishedDocumentJson)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedSuccessorPublicKey);
        ArgumentNullException.ThrowIfNull(publishedDocumentJson);

        if (!ValidPins(didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey) ||
            publishedDocumentJson.Length is 0 or > MaximumDocumentCharacters)
        {
            return false;
        }

        try
        {
            using JsonDocument expected = JsonDocument.Parse(CreateRetirementDocument(
                didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey));
            using JsonDocument actual = JsonDocument.Parse(publishedDocumentJson,
                new JsonDocumentOptions
                {
                    MaxDepth = 8,
                    CommentHandling = JsonCommentHandling.Disallow,
                    AllowTrailingCommas = false
                });
            return DidWebPinnedKeyTransition.MatchesExactly(
                actual.RootElement, expected.RootElement);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            // Malformed Unicode escapes can fail during deferred JSON access.
            return false;
        }
    }

    /// <summary>
    /// Fetch a successor-only published did:web document at its exact
    /// canonical HTTPS URI and check both independent operator pins.
    /// A caller-supplied HttpClient MUST disable redirects, credentials,
    /// cookies, proxies and request baggage before invoking this API.
    /// </summary>
    public static async Task<bool> FetchAndMatchAsync(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedSuccessorPublicKey);
        ArgumentNullException.ThrowIfNull(http);

        if (!ValidPins(didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey) ||
            http.DefaultRequestHeaders.Any())
        {
            return false;
        }

        return await DidWebPinnedDocumentHttpTransport.FetchAndMatchDocumentAsync(
            didIdentifier, http,
            json => MatchesExpectedRetirementDocument(
                didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey, json),
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetch with the shared bounded isolated public-only HTTPS transport,
    /// without promoting the successor or changing credential trust.
    /// Network operators remain responsible for independent egress policy.
    /// </summary>
    public static async Task<bool> FetchAndMatchWithIsolatedTransportAsync(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = DidWebPinnedDocumentHttpTransport.CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler, disposeHandler: false);
        return await FetchAndMatchAsync(didIdentifier, pinnedOldPublicKey,
            pinnedSuccessorPublicKey, http, maximumDuration,
            cancellationToken).ConfigureAwait(false);
    }

    private static bool ValidPins(
        string didIdentifier, byte[] oldKey, byte[] successorKey) =>
        new DidWebMethod().IsValid(didIdentifier) &&
        oldKey.Length == 32 &&
        successorKey.Length == 32 &&
        !CryptographicOperations.FixedTimeEquals(oldKey, successorKey);
}
