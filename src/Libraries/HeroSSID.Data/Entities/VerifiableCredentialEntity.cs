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
    /// Schema used for this credential (foreign key)
    /// </summary>
    public Guid SchemaId { get; set; }

    /// <summary>
    /// Navigation property: Schema
    /// </summary>
    public CredentialSchemaEntity? Schema { get; set; }

    /// <summary>
    /// Credential definition used (foreign key)
    /// </summary>
    public Guid CredentialDefinitionId { get; set; }

    /// <summary>
    /// Navigation property: Credential Definition
    /// </summary>
    public CredentialDefinitionEntity? CredentialDefinition { get; set; }

    /// <summary>
    /// Full W3C Verifiable Credential as JSON (includes proof)
    /// </summary>
    public required string CredentialJson { get; set; }

    /// <summary>
    /// When the credential was issued
    /// </summary>
    public DateTimeOffset IssuedAt { get; set; }

    /// <summary>
    /// Optional expiration date (null = no expiration)
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }
}
