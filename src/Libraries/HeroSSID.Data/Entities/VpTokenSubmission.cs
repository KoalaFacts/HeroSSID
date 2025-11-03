namespace HeroSSID.Data.Entities;

/// <summary>
/// Stores wallet-submitted VP Tokens for verification.
/// </summary>
public class VpTokenSubmission
{
    /// <summary>
    /// Unique submission identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// References the presentation request.
    /// </summary>
    public Guid PresentationRequestId { get; set; }

    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// The JWT VP Token from wallet.
    /// </summary>
    public string VpToken { get; set; } = string.Empty;

    /// <summary>
    /// Extracted disclosed claims, stored as JSON.
    /// </summary>
    public string? DisclosedClaims { get; set; }

    /// <summary>
    /// DID of credential holder.
    /// </summary>
    public Guid? HolderDidId { get; set; }

    /// <summary>
    /// Verification status: VALID, INVALID, EXPIRED, REVOKED.
    /// </summary>
    public string VerificationStatus { get; set; } = string.Empty;

    /// <summary>
    /// Error details if verification failed, stored as JSON.
    /// </summary>
    public string? VerificationErrors { get; set; }

    /// <summary>
    /// When wallet submitted.
    /// </summary>
    public DateTimeOffset SubmittedAt { get; set; }

    /// <summary>
    /// When verification completed.
    /// </summary>
    public DateTimeOffset? VerifiedAt { get; set; }

    // Navigation properties
    public PresentationRequest? PresentationRequest { get; set; }
    public DidEntity? HolderDid { get; set; }
}
