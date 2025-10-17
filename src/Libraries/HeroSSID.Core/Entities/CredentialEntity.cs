namespace HeroSSID.Core.Entities;

/// <summary>
/// Represents a Verifiable Credential stored in the system
/// </summary>
public sealed class CredentialEntity
{
    /// <summary>
    /// Primary key
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// JWT token of the credential
    /// </summary>
    public required string Jwt { get; init; }

    /// <summary>
    /// Issuer DID (foreign key)
    /// </summary>
    public required Guid IssuerDidId { get; init; }

    /// <summary>
    /// Navigation property: Issuer DID
    /// </summary>
    public DidEntity? IssuerDid { get; init; }

    /// <summary>
    /// Subject DID (foreign key)
    /// </summary>
    public required Guid SubjectDidId { get; init; }

    /// <summary>
    /// Navigation property: Subject DID
    /// </summary>
    public DidEntity? SubjectDid { get; init; }

    /// <summary>
    /// Credential type (e.g., "UniversityDegreeCredential")
    /// </summary>
    public required string CredentialType { get; init; }

    /// <summary>
    /// Credential subject claims (JSON string)
    /// </summary>
    public required string CredentialSubject { get; init; }

    /// <summary>
    /// When the credential was issued
    /// </summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// When the credential expires (null if no expiration)
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// Indicates if this credential has been revoked
    /// </summary>
    public bool IsRevoked { get; init; }

    /// <summary>
    /// When the credential was revoked (null if not revoked)
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// When this record was created
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
}
