namespace HeroSSID.Data.Entities;

/// <summary>
/// Stores OpenID4VP presentation requests from verifiers.
/// </summary>
public class PresentationRequest
{
    /// <summary>
    /// Unique request identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// DID of verifier (if registered).
    /// </summary>
    public Guid? VerifierDidId { get; set; }

    /// <summary>
    /// Presentation Exchange 2.0 definition, stored as JSON.
    /// </summary>
    public string PresentationDefinitionJson { get; set; } = string.Empty;

    /// <summary>
    /// Cryptographic nonce to prevent replay attacks (256-bit minimum).
    /// </summary>
    public string Nonce { get; set; } = string.Empty;

    /// <summary>
    /// Where wallet POSTs VP Token.
    /// </summary>
    #pragma warning disable CA1056 // URI properties should not be strings - stored as string in database
    public string ResponseUri { get; set; } = string.Empty;
    #pragma warning restore CA1056

    /// <summary>
    /// Full openid4vp:// URI.
    /// </summary>
    #pragma warning disable CA1056 // URI properties should not be strings - stored as string in database
    public string RequestUri { get; set; } = string.Empty;
    #pragma warning restore CA1056

    /// <summary>
    /// OAuth state parameter.
    /// </summary>
    public string State { get; set; } = string.Empty;

    /// <summary>
    /// Request expiration (default: 15 minutes).
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Creation timestamp.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When wallet submitted VP.
    /// </summary>
    public DateTimeOffset? RespondedAt { get; set; }

    // Navigation properties
    public DidEntity? VerifierDid { get; set; }

    #pragma warning disable CA2227 // Collection properties should be read only - EF Core requires setter
    public ICollection<VpTokenSubmission> VpTokenSubmissions { get; set; } = new List<VpTokenSubmission>();
    #pragma warning restore CA2227
}
