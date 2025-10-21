namespace HeroSSID.DidOperations.DidResolution;

/// <summary>
/// Result of a DID resolution operation.
/// Follows W3C DID Core Resolution specification.
/// Reference: https://www.w3.org/TR/did-core/#did-resolution
/// </summary>
public sealed class DidResolutionResult
{
    /// <summary>
    /// The DID that was resolved
    /// </summary>
    public required string DidIdentifier { get; init; }

    /// <summary>
    /// The resolved DID Document as JSON
    /// </summary>
    public string? DidDocument { get; init; }

    /// <summary>
    /// Resolution metadata containing information about the resolution process
    /// </summary>
    public required DidResolutionMetadata Metadata { get; init; }

    /// <summary>
    /// Whether the resolution was successful
    /// </summary>
    public bool IsSuccess => Metadata.Error == null;
}

/// <summary>
/// Metadata about the DID resolution process.
/// Reference: https://www.w3.org/TR/did-core/#did-resolution-metadata
/// </summary>
public sealed class DidResolutionMetadata
{
    /// <summary>
    /// Content type of the DID Document (e.g., "application/did+ld+json")
    /// </summary>
    public string? ContentType { get; init; }

    /// <summary>
    /// Error code if resolution failed.
    /// Standard error codes: "notFound", "invalidDid", "methodNotSupported"
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Human-readable error message
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Creates successful resolution metadata
    /// </summary>
    public static DidResolutionMetadata CreateSuccess(string contentType = "application/did+ld+json")
        => new() { ContentType = contentType };

    /// <summary>
    /// Creates error resolution metadata
    /// </summary>
    public static DidResolutionMetadata CreateError(string errorCode, string errorMessage)
        => new() { Error = errorCode, ErrorMessage = errorMessage };
}
