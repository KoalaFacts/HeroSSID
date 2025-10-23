namespace HeroSSID.Data.Entities;

/// <summary>
/// Stores pre-authorized codes for OpenID4VCI wallet credential issuance.
/// </summary>
public class PreAuthorizedCode
{
    /// <summary>
    /// Unique identifier for the pre-authorized code.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// The pre-authorized code value (cryptographically secure random, 256-bit minimum).
    /// </summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>
    /// References the credential offer.
    /// </summary>
    public Guid CredentialOfferId { get; set; }

    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// The DID issuing the credential.
    /// </summary>
    public Guid IssuerDidId { get; set; }

    /// <summary>
    /// The DID receiving the credential (if known).
    /// </summary>
    public Guid? HolderDidId { get; set; }

    /// <summary>
    /// Array of credential types offered (e.g., ["UniversityDegreeCredential"]) stored as JSON.
    /// </summary>
    public string CredentialTypes { get; set; } = string.Empty;

    /// <summary>
    /// The claims to include in credential, stored as JSON.
    /// </summary>
    public string CredentialSubject { get; set; } = string.Empty;

    /// <summary>
    /// Optional PIN/code for QR security (6 digits numeric if present).
    /// </summary>
    public string? TransactionCode { get; set; }

    /// <summary>
    /// Code expiration (default: 5 minutes from creation).
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// When code was exchanged for credential.
    /// </summary>
    public DateTimeOffset? RedeemedAt { get; set; }

    /// <summary>
    /// Creation timestamp.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Whether code was manually revoked.
    /// </summary>
    public bool IsRevoked { get; set; }

    // Navigation properties
    public DidEntity? IssuerDid { get; set; }
    public DidEntity? HolderDid { get; set; }
    public CredentialOffer? CredentialOffer { get; set; }
}
