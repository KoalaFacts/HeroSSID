using HeroSSID.DidOperations.Models;

namespace HeroSSID.DidOperations.Interfaces;

/// <summary>
/// Service for creating W3C-compliant Decentralized Identifiers (DIDs)
/// </summary>
public interface IDidCreationService
{
    /// <summary>
    /// Creates a new DID with key pair, DID Document, and stores in database
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Result containing DID information</returns>
    public Task<DidCreationResult> CreateDidAsync(CancellationToken cancellationToken = default);
}
