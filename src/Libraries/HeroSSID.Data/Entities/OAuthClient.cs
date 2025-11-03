namespace HeroSSID.Data.Entities;

/// <summary>
/// OAuth 2.0 client for client credentials authentication.
/// </summary>
public class OAuthClient
{
    /// <summary>
    /// Unique identifier for the client.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Client identifier used for authentication.
    /// </summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// Hashed client secret for authentication.
    /// </summary>
    public required string ClientSecretHash { get; set; }

    /// <summary>
    /// Display name for the client.
    /// </summary>
    public required string DisplayName { get; set; }

    /// <summary>
    /// Tenant identifier for multi-tenant isolation.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Space-separated list of allowed scopes for this client.
    /// </summary>
    public string Scopes { get; set; } = string.Empty;

    /// <summary>
    /// Whether the client is enabled.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Creation timestamp.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
