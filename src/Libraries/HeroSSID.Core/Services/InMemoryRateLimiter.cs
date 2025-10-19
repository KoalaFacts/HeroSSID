using System.Collections.Concurrent;
using HeroSSID.Core.Interfaces;

namespace HeroSSID.Core.Services;

/// <summary>
/// In-memory rate limiter using sliding window algorithm
/// For MVP/development - replace with distributed cache (Redis) for production
/// </summary>
/// <remarks>
/// SECURITY: Prevents resource exhaustion attacks by limiting operations per tenant per time window.
/// Default limits: 100 operations per 60 seconds per tenant per operation type.
/// NOTE: This is an in-memory implementation and will not work across multiple server instances.
/// For production, replace with distributed rate limiting (Redis, etc.)
/// </remarks>
public sealed class InMemoryRateLimiter : IRateLimiter
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _operationLog = new();
    private readonly TimeSpan _windowSize;
    private readonly int _maxOperations;

    /// <summary>
    /// Initializes rate limiter with default limits
    /// </summary>
    /// <param name="windowSize">Time window for rate limiting (default: 60 seconds)</param>
    /// <param name="maxOperations">Maximum operations per window (default: 100)</param>
    public InMemoryRateLimiter(TimeSpan? windowSize = null, int maxOperations = 100)
    {
        _windowSize = windowSize ?? TimeSpan.FromSeconds(60);
        _maxOperations = maxOperations;
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
}
