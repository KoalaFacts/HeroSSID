namespace HeroSSID.Core.Services;

/// <summary>
/// Interface for rate limiting transaction code attempts to prevent brute force attacks.
/// </summary>
public interface ITransactionCodeRateLimiter
{
    /// <summary>
    /// Checks if a transaction code attempt is allowed for the given pre-authorized code.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    /// <returns>True if the attempt is allowed, false if rate limit exceeded.</returns>
    public bool IsAttemptAllowed(string preAuthorizedCodeId);

    /// <summary>
    /// Records a failed transaction code attempt.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    public void RecordFailedAttempt(string preAuthorizedCodeId);

    /// <summary>
    /// Resets the attempt counter for a pre-authorized code (e.g., after successful redemption).
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    public void ResetAttempts(string preAuthorizedCodeId);

    /// <summary>
    /// Gets the number of remaining attempts for a pre-authorized code.
    /// </summary>
    /// <param name="preAuthorizedCodeId">The pre-authorized code identifier.</param>
    /// <returns>Number of remaining attempts (0-3).</returns>
    public int GetRemainingAttempts(string preAuthorizedCodeId);
}
