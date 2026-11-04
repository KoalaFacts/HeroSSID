namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Opt-in HTTPS transport for an independently pinned did:web and Ed25519 key.
/// The caller must preapprove the DID and maintain safe DNS/TLS/SSRF policy.
/// </summary>
public static class DidWebPinnedDocumentHttpTransport
{
    /// <summary>
    /// Fetch the exact did:web publication URI and accept only an original
    /// single-key DID document matching the independently pinned key.
    /// </summary>
    public static Task<bool> FetchAndMatchAsync(
        string didIdentifier, byte[] expectedPublicKey, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(expectedPublicKey);
        ArgumentNullException.ThrowIfNull(http);
        throw new NotSupportedException("Implement bounded pinned did:web HTTPS GET.");
    }
}
