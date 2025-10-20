namespace HeroSSID.Data.Entities;

/// <summary>
/// Represents a W3C-compliant Decentralized Identifier (DID)
/// </summary>
public sealed class DidEntity
{
    /// <summary>
    /// Internal database ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Tenant ID (hardcoded to 11111111-1111-1111-1111-111111111111 for MVP)
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Full DID identifier (e.g., did:web:example.com:user:alice or did:key:z6Mkf5rGMo...)
    /// </summary>
    public required string DidIdentifier { get; set; }

    /// <summary>
    /// Ed25519 public signing key (32 bytes)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Required for EF Core binary data mapping")]
    public required byte[] PublicKeyEd25519 { get; set; }

    /// <summary>
    /// SHA-256 fingerprint of the public key for key reuse detection (32 bytes)
    /// </summary>
    /// <remarks>
    /// SECURITY: Used to detect if the same cryptographic key is being reused across multiple DIDs,
    /// which is a security anti-pattern that reduces key isolation.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Required for EF Core binary data mapping")]
    public required byte[] KeyFingerprint { get; set; }

    /// <summary>
    /// Encrypted Ed25519 private key (variable length)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Required for EF Core binary data mapping")]
    public required byte[] PrivateKeyEd25519Encrypted { get; set; }

    /// <summary>
    /// W3C DID Document as JSON
    /// </summary>
    public required string DidDocumentJson { get; set; }

    /// <summary>
    /// DID status: 'active' or 'deactivated'
    /// </summary>
    public string Status { get; set; } = "active";

    /// <summary>
    /// When this DID was created
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    // Navigation properties
    public ICollection<VerifiableCredentialEntity> IssuedCredentials { get; init; } = new List<VerifiableCredentialEntity>();
    public ICollection<VerifiableCredentialEntity> HeldCredentials { get; init; } = new List<VerifiableCredentialEntity>();
}
