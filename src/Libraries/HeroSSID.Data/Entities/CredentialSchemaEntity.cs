namespace HeroSSID.Data.Entities;

/// <summary>
/// Represents a W3C Verifiable Credential schema
/// </summary>
public sealed class CredentialSchemaEntity
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
    /// Human-readable schema name (e.g., "UniversityDegree")
    /// </summary>
    public required string SchemaName { get; set; }

    /// <summary>
    /// Semantic version (e.g., "1.0.0")
    /// </summary>
    public required string SchemaVersion { get; set; }

    /// <summary>
    /// Attribute names (e.g., ["name", "degree", "year"])
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Required for PostgreSQL array column mapping")]
    public required string[] Attributes { get; set; }

    /// <summary>
    /// Schema identifier URL (e.g., "https://example.com/schemas/UniversityDegree/v1.0.0")
    /// </summary>
    public required string SchemaId { get; set; }

    /// <summary>
    /// DID that published this schema (foreign key)
    /// </summary>
    public Guid PublisherDidId { get; set; }

    /// <summary>
    /// Navigation property: Publisher DID
    /// </summary>
    public DidEntity? PublisherDid { get; set; }

    /// <summary>
    /// When this schema was created
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    // Navigation properties
    public ICollection<CredentialDefinitionEntity> CredentialDefinitions { get; init; } = new List<CredentialDefinitionEntity>();
    public ICollection<VerifiableCredentialEntity> Credentials { get; init; } = new List<VerifiableCredentialEntity>();
}
