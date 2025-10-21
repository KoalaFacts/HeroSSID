using System.Collections.Concurrent;

namespace HeroSSID.Core.RateLimiting;

/// <summary>
/// In-memory rate limiter using sliding window algorithm
/// For MVP/development - replace with distributed cache (Redis) for production
/// </summary>
/// <remarks>
/// SECURITY: Prevents resource exhaustion attacks by limiting operations per tenant per time window.
/// Default limits: 100 operations per 60 seconds per tenant per operation type.
/// NOTE: This is an in-memory implementation and will not work across multiple server instances.
/// For production, replace with distributed rate limiting (Redis, etc.)
///
/// MEMORY MANAGEMENT: Periodically cleans up expired entries to prevent memory exhaustion.
/// Cleanup runs every 5 minutes and removes entries with no operations in the last window.
/// </remarks>
public sealed class InMemoryRateLimiter : IRateLimiter, IDisposable
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _operationLog = new();
    private readonly TimeSpan _windowSize;
    private readonly int _maxOperations;
    private readonly Timer? _cleanupTimer;
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Initializes rate limiter with default limits
    /// </summary>
    /// <param name="windowSize">Time window for rate limiting (default: 60 seconds)</param>
    /// <param name="maxOperations">Maximum operations per window (default: 100)</param>
    public InMemoryRateLimiter(TimeSpan? windowSize = null, int maxOperations = 100)
    {
        _windowSize = windowSize ?? TimeSpan.FromSeconds(60);
        _maxOperations = maxOperations;

        // SECURITY: Start periodic cleanup to prevent memory exhaustion from abandoned keys
        _cleanupTimer = new Timer(
            callback: _ => CleanupExpiredEntries(),
            state: null,
            dueTime: _cleanupInterval,
            period: _cleanupInterval);
    }

    /// <inheritdoc />
    public Task<bool> IsAllowedAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationType);

        string key = GetKey(tenantId, operationType);
        var queue = _operationLog.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>());

        // Remove expired entries from the sliding window
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - _windowSize;
        while (queue.TryPeek(out DateTimeOffset timestamp) && timestamp < cutoff)
        {
            queue.TryDequeue(out _);
        }

        // Check if current count is below limit
        bool isAllowed = queue.Count < _maxOperations;
        return Task.FromResult(isAllowed);
    }

    /// <inheritdoc />
    public Task RecordOperationAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationType);

        string key = GetKey(tenantId, operationType);
        var queue = _operationLog.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>());

        queue.Enqueue(DateTimeOffset.UtcNow);

        return Task.CompletedTask;
    }

    private static string GetKey(Guid tenantId, string operationType)
        => $"{tenantId}:{operationType}";

    /// <summary>
    /// Periodically cleans up expired entries to prevent memory exhaustion
    /// Removes dictionary keys where all queue entries are older than the time window
    /// </summary>
    private void CleanupExpiredEntries()
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - _windowSize;

        foreach (var kvp in _operationLog)
        {
            var queue = kvp.Value;

            // Remove expired entries from the queue
            while (queue.TryPeek(out DateTimeOffset timestamp) && timestamp < cutoff)
            {
                queue.TryDequeue(out _);
            }

            // If queue is now empty, remove the key from the dictionary to free memory
            if (queue.IsEmpty)
            {
                _operationLog.TryRemove(kvp.Key, out _);
            }
        }
    }

    /// <summary>
    /// Disposes the rate limiter and stops the cleanup timer
    /// </summary>
    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }
}
