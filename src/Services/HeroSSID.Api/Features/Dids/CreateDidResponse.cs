namespace HeroSSID.Api.Features.Dids;

/// <summary>
/// Response after creating a new DID
/// </summary>
public sealed record CreateDidResponse
{
    /// <summary>
    /// The created DID identifier
    /// </summary>
    public required string Did { get; init; }

    /// <summary>
    /// W3C DID Document for the created DID
    /// </summary>
    public required object DidDocument { get; init; }
}
