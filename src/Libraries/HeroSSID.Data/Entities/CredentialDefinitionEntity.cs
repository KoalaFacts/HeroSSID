namespace HeroSSID.Data.Entities;

/// <summary>
/// Represents a W3C Verifiable Credential definition
/// </summary>
public sealed class CredentialDefinitionEntity
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
    /// Schema this credential definition is based on (foreign key)
    /// </summary>
    public Guid SchemaId { get; set; }

    /// <summary>
    /// Navigation property: Schema
    /// </summary>
    public CredentialSchemaEntity? Schema { get; set; }

    /// <summary>
    /// DID that created this credential definition (foreign key)
    /// </summary>
    public Guid IssuerDidId { get; set; }

    /// <summary>
    /// Navigation property: Issuer DID
    /// </summary>
    public DidEntity? IssuerDid { get; set; }

    /// <summary>
    /// Credential definition identifier URL
    /// </summary>
    public required string CredentialDefinitionId { get; set; }

    /// <summary>
    /// Whether this credential definition supports revocation (always false in MVP)
    /// </summary>
    public bool SupportsRevocation { get; set; }

    /// <summary>
    /// When this credential definition was created
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    // Navigation properties
    public ICollection<VerifiableCredentialEntity> Credentials { get; init; } = new List<VerifiableCredentialEntity>();
}
