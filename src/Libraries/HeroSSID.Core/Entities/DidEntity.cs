namespace HeroSSID.Core.Entities;

/// <summary>
/// Represents a DID (Decentralized Identifier) stored in the system
/// </summary>
public sealed class DidEntity
{
    /// <summary>
    /// Primary key
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// The DID string (e.g., "did:key:z6Mkf5rG...")
    /// </summary>
    public required string Did { get; init; }

    /// <summary>
    /// DID method (e.g., "key", "web")
    /// </summary>
    public required string Method { get; init; }

    /// <summary>
    /// Encrypted private key (JWK format, encrypted using Data Protection API)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Required for EF Core binary data mapping")]
    public required byte[] EncryptedPrivateKey { get; init; }

    /// <summary>
    /// Public key in JWK format (JSON string)
    /// </summary>
    public required string PublicKeyJwk { get; init; }

    /// <summary>
    /// DID Document (JSON string)
    /// </summary>
    public required string DidDocument { get; init; }

    /// <summary>
    /// Optional human-readable alias for this DID
    /// </summary>
    public string? Alias { get; init; }

    /// <summary>
    /// Indicates if this DID is currently active
    /// </summary>
    public bool IsActive { get; init; } = true;

    /// <summary>
    /// When this DID was created
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// When this DID was last used
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; init; }

    /// <summary>
    /// Navigation property: Credentials issued by this DID
    /// </summary>
    public ICollection<CredentialEntity> IssuedCredentials { get; init; } = [];

    /// <summary>
    /// Navigation property: Credentials received by this DID
    /// </summary>
    public ICollection<CredentialEntity> ReceivedCredentials { get; init; } = [];
}
