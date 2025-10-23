using System.Collections.Concurrent;

namespace HeroSSID.Core.Services;

/// <summary>
/// Rate limiter specifically for transaction code attempts to prevent brute force attacks.
/// </summary>
/// <remarks>
/// Transaction codes are 6-digit PINs (1,000,000 possible combinations).
/// Without rate limiting, an attacker could brute force all combinations.
/// This limiter allows only 3 attempts per pre-authorized code within a 5-minute window.
/// </remarks>
public sealed class TransactionCodeRateLimiter : ITransactionCodeRateLimiter, IDisposable
{
    private readonly ConcurrentDictionary<string, AttemptTracker> _attemptTrackers = new();
    private readonly Timer _cleanupTimer;
    private const int MaxAttempts = 3;
    private static readonly TimeSpan WindowDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

    public TransactionCodeRateLimiter()
    {
        // Periodically clean up expired trackers to prevent memory leaks
        _cleanupTimer = new Timer(CleanupExpiredTrackers, null, CleanupInterval, CleanupInterval);
    }

    /// <summary>
    /// Checks if a transaction code attempt is allowed for the given pre-authorized code.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    /// <returns>True if the attempt is allowed, false if rate limit exceeded.</returns>
    public bool IsAttemptAllowed(string preAuthorizedCodeId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(preAuthorizedCodeId);

        var tracker = _attemptTrackers.GetOrAdd(preAuthorizedCodeId, _ => new AttemptTracker());

        lock (tracker)
        {
            var now = DateTimeOffset.UtcNow;

            // Remove attempts outside the window
            tracker.Attempts.RemoveWhere(attempt => now - attempt > WindowDuration);

            // Check if limit exceeded
            if (tracker.Attempts.Count >= MaxAttempts)
            {
                return false;
            }

            // Record this attempt
            tracker.Attempts.Add(now);
            tracker.LastAttemptTime = now;

            return true;
        }
    }

    /// <summary>
    /// Records a failed transaction code attempt.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    public void RecordFailedAttempt(string preAuthorizedCodeId)
    {
        // Attempt is already recorded in IsAttemptAllowed
        // This method is here for semantic clarity and future extensibility
        ArgumentException.ThrowIfNullOrWhiteSpace(preAuthorizedCodeId);
    }

    /// <summary>
    /// Resets the attempt counter for a pre-authorized code (e.g., after successful redemption).
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    public void ResetAttempts(string preAuthorizedCodeId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(preAuthorizedCodeId);
        _attemptTrackers.TryRemove(preAuthorizedCodeId, out _);
    }

    /// <summary>
    /// Gets the number of remaining attempts for a pre-authorized code.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    /// <returns>Number of remaining attempts (0-3).</returns>
    public int GetRemainingAttempts(string preAuthorizedCodeId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(preAuthorizedCodeId);

        if (!_attemptTrackers.TryGetValue(preAuthorizedCodeId, out var tracker))
        {
            return MaxAttempts;
        }

        lock (tracker)
        {
            var now = DateTimeOffset.UtcNow;
            tracker.Attempts.RemoveWhere(attempt => now - attempt > WindowDuration);
            return Math.Max(0, MaxAttempts - tracker.Attempts.Count);
        }
    }

    private void CleanupExpiredTrackers(object? state)
    {
        var now = DateTimeOffset.UtcNow;
        var expiredKeys = _attemptTrackers
            .Where(kvp => now - kvp.Value.LastAttemptTime > WindowDuration)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _attemptTrackers.TryRemove(key, out _);
        }
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }

    private sealed class AttemptTracker
    {
        public HashSet<DateTimeOffset> Attempts { get; } = [];
        public DateTimeOffset LastAttemptTime { get; set; }
    }
}
