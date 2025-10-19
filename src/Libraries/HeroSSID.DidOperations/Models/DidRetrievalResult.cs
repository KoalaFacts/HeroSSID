namespace HeroSSID.DidOperations.Models;

/// <summary>
/// Result of retrieving a DID from the database by ID.
/// Similar to DidCreationResult but without sensitive private key material.
/// </summary>
public sealed class DidRetrievalResult
{
    /// <summary>
    /// Internal database ID
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Tenant ID
    /// </summary>
    public required Guid TenantId { get; init; }

    /// <summary>
    /// Full DID identifier (e.g., did:key:z6Mkf5rGMo...)
    /// </summary>
    public required string DidIdentifier { get; init; }

    /// <summary>
    /// Ed25519 public key (32 bytes)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "DTO for cryptographic keys")]
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// W3C DID Document as JSON
    /// </summary>
    public required string DidDocumentJson { get; init; }

    /// <summary>
    /// DID status (e.g., "active", "revoked", "deactivated")
    /// </summary>
    public required string Status { get; init; }

    /// <summary>
    /// When the DID was created
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
}
