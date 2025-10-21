namespace HeroSSID.DidOperations.DidResolution;

/// <summary>
/// Service for resolving Decentralized Identifiers (DIDs) to their DID Documents.
/// Implements W3C DID Core Resolution specification.
/// </summary>
public interface IDidResolutionService
{
    /// <summary>
    /// Resolves a DID to its DID Document.
    /// </summary>
    /// <param name="didIdentifier">The DID to resolve (e.g., "did:key:z6Mk...")</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Resolution result containing DID Document or error information</returns>
    public Task<DidResolutionResult> ResolveAsync(string didIdentifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a DID by its database ID.
    /// </summary>
    /// <param name="id">Database ID of the DID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>DID retrieval result or null if not found</returns>
    public Task<DidRetrievalResult?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a DID exists in the database.
    /// </summary>
    /// <param name="didIdentifier">The DID to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the DID exists, false otherwise</returns>
    public Task<bool> ExistsAsync(string didIdentifier, CancellationToken cancellationToken = default);
}
