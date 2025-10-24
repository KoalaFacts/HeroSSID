namespace HeroSSID.Api.Features.Dids;

/// <summary>
/// Request to create a new DID
/// </summary>
public sealed record CreateDidRequest
{
    /// <summary>
    /// DID method to use (e.g., "did:key")
    /// </summary>
    public required string Method { get; init; }

    /// <summary>
    /// Key type for the DID (e.g., "Ed25519")
    /// </summary>
    public required string KeyType { get; init; }
}
