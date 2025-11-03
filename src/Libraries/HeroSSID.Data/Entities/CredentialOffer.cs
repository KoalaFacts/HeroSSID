namespace HeroSSID.Data.Entities;

/// <summary>
/// Stores metadata about credential offers (referenced by QR codes).
/// </summary>
public class CredentialOffer
{
    /// <summary>
    /// Unique offer identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// The full credential offer URI (format: openid-credential-offer://?credential_offer_uri=...).
    /// </summary>
    #pragma warning disable CA1056 // URI properties should not be strings - stored as string in database
    public string OfferUri { get; set; } = string.Empty;
    #pragma warning restore CA1056

    /// <summary>
    /// Base URL of issuer (e.g., https://herossid.au).
    /// </summary>
    public string CredentialIssuer { get; set; } = string.Empty;

    /// <summary>
    /// References the pre-authorized code.
    /// </summary>
    public Guid PreAuthorizedCodeId { get; set; }

    /// <summary>
    /// PNG QR code image (if generated).
    /// </summary>
    #pragma warning disable CA1819 // Properties should not return arrays - byte array for binary data
    public byte[]? QrCodeImage { get; set; }
    #pragma warning restore CA1819

    /// <summary>
    /// Creation timestamp.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Offer expiration.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// When wallet first accessed offer metadata.
    /// </summary>
    public DateTimeOffset? AccessedAt { get; set; }

    // Navigation properties
    public PreAuthorizedCode? PreAuthorizedCode { get; set; }
}
