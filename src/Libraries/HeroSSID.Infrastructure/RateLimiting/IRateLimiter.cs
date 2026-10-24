namespace HeroSSID.Infrastructure.RateLimiting;

/// <summary>
/// Rate limiting service to prevent resource exhaustion attacks
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Atomically reserves one operation within the active sliding window.
    /// Rejected admission does not consume capacity. For enforcement use this call:
    /// a separate check and record allows concurrent oversubscription.
    /// </summary>
    /// <param name="tenantId">The authenticated requester tenant</param>
    /// <param name="operationType">Operation category</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Whether one permit was reserved</returns>
    public Task<bool> TryAcquireAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default);

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
