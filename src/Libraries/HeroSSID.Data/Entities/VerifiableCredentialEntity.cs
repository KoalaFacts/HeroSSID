namespace HeroSSID.Data.Entities;

/// <summary>
/// Represents an issued W3C Verifiable Credential
/// </summary>
public sealed class VerifiableCredentialEntity
{
    /// <summary>
    /// Internal database ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Tenant ID (hardcoded for MVP)
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// DID that issued the credential (foreign key)
    /// </summary>
    public Guid IssuerDidId { get; set; }

    /// <summary>
    /// Navigation property: Issuer DID
    /// </summary>
    public DidEntity? IssuerDid { get; set; }

    /// <summary>
    /// DID that holds the credential (foreign key)
    /// </summary>
    public Guid HolderDidId { get; set; }

    /// <summary>
    /// Navigation property: Holder DID
    /// </summary>
    public DidEntity? HolderDid { get; set; }

    /// <summary>
    /// Credential type (e.g., "UniversityDegreeCredential")
    /// </summary>
    public required string CredentialType { get; set; }

    /// <summary>
    /// Full JWT-VC string (signed, base64-encoded W3C Verifiable Credential)
    /// </summary>
    public required string CredentialJwt { get; set; }

    /// <summary>
    /// Credential status: "active", "revoked"
    /// </summary>
    public required string Status { get; set; } = "active";

    /// <summary>
    /// When the credential was issued
    /// </summary>
    public DateTimeOffset IssuedAt { get; set; }

    /// <summary>
    /// Optional expiration date (null = no expiration)
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// Entity creation timestamp (auto-set)
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Entity last update timestamp (auto-set)
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
