namespace HeroSSID.Infrastructure.RateLimiting;

/// <summary>
/// Rate limiting service to prevent resource exhaustion attacks
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Checks if an operation is allowed under current rate limits
    /// </summary>
    /// <param name="tenantId">Tenant identifier for rate limit tracking</param>
    /// <param name="operationType">Type of operation (e.g., "DID_CREATE", "DID_SIGN")</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if operation is allowed, false if rate limit exceeded</returns>
    public Task<bool> IsAllowedAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records an operation for rate limiting tracking
    /// </summary>
    /// <param name="tenantId">Tenant identifier</param>
    /// <param name="operationType">Type of operation</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public Task RecordOperationAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default);
}
