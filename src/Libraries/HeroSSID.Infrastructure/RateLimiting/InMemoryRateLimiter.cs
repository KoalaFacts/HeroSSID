namespace HeroSSID.Infrastructure.RateLimiting;

/// <summary>
/// Process-local sliding-window limiter with atomic reservation.
/// Separate instances do not coordinate their quotas.
/// </summary>
/// <remarks>
/// A shared gate serializes reservation, observation, recording, and expiry cleanup.
/// The legacy check and record methods must not be combined for enforcement.
/// </remarks>
public sealed class InMemoryRateLimiter : IRateLimiter, IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _operationLog = new(StringComparer.Ordinal);
    private readonly TimeSpan _windowSize;
    private readonly int _maxOperations;
    private readonly TimeProvider _clock;
    private readonly Timer _cleanupTimer;
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);

    /// <summary>Configures the sliding window, capacity, and optional testing clock.</summary>
    public InMemoryRateLimiter(TimeSpan? windowSize = null, int maxOperations = 100, TimeProvider? timeProvider = null)
    {
        if (windowSize.HasValue && windowSize.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(windowSize));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxOperations);
        _windowSize = windowSize ?? TimeSpan.FromSeconds(60);
        _maxOperations = maxOperations;
        _clock = timeProvider ?? TimeProvider.System;

        _cleanupTimer = new Timer(
            callback: _ => CleanupExpiredEntries(),
            state: null,
            dueTime: _cleanupInterval,
            period: _cleanupInterval);
    }

    /// <inheritdoc />
    public Task<bool> TryAcquireAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(operationType);

        lock (_gate)
        {
            var now = _clock.GetUtcNow();
            var queue = GetOrCreateWindow(GetKey(tenantId, operationType));
            RemoveExpired(queue, now - _windowSize);
            if (queue.Count >= _maxOperations)
            {
                return Task.FromResult(false);
            }

            queue.Enqueue(now);
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<bool> IsAllowedAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(operationType);

        lock (_gate)
        {
            var queue = GetOrCreateWindow(GetKey(tenantId, operationType));
            RemoveExpired(queue, _clock.GetUtcNow() - _windowSize);
            return Task.FromResult(queue.Count < _maxOperations);
        }
    }

    /// <inheritdoc />
    public Task RecordOperationAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(operationType);

        lock (_gate)
        {
            // Observation/recording compatibility only. Enforcement must use TryAcquireAsync.
            GetOrCreateWindow(GetKey(tenantId, operationType)).Enqueue(_clock.GetUtcNow());
        }

        return Task.CompletedTask;
    }

    private Queue<DateTimeOffset> GetOrCreateWindow(string key)
    {
        if (!_operationLog.TryGetValue(key, out var queue))
        {
            queue = new Queue<DateTimeOffset>();
            _operationLog.Add(key, queue);
        }

        return queue;
    }

    private static void RemoveExpired(Queue<DateTimeOffset> queue, DateTimeOffset cutoff)
    {
        while (queue.Count != 0 && queue.Peek() < cutoff)
        {
            queue.Dequeue();
        }
    }

    private static string GetKey(Guid tenantId, string operationType) => $"{tenantId}:{operationType}";

    private void CleanupExpiredEntries()
    {
        lock (_gate)
        {
            var cutoff = _clock.GetUtcNow() - _windowSize;
            foreach (var key in _operationLog.Keys.ToArray())
            {
                var queue = _operationLog[key];
                RemoveExpired(queue, cutoff);
                if (queue.Count == 0)
                {
                    _operationLog.Remove(key);
                }
            }
        }
    }

    /// <inheritdoc />
    public void Dispose() => _cleanupTimer.Dispose();
}
