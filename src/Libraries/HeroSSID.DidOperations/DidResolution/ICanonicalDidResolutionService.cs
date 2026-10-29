namespace HeroSSID.DidOperations.DidResolution;

/// <summary>
/// Opt-in canonical did:key compatibility projection. This separate interface preserves
/// existing custom implementations of IDidResolutionService.
/// </summary>
public interface ICanonicalDidResolutionService
{
    /// <summary>
    /// Derives an Ed25519 did:key document from a tenant-owned active record's public key
    /// without trusting or rewriting its legacy stored JSON. Rejects key/DID mismatches.
    /// </summary>
    public Task<DidResolutionResult> ResolveCanonicalDidKeyAsync(
        string didIdentifier, CancellationToken cancellationToken = default);
}
