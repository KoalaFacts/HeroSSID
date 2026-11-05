namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Independent retired-successor DID publication and one-use Ed25519 key-control
/// admission. This opt-in profile never grants issuer trust or authorization.
/// </summary>
public sealed class DidWebPinnedRetiredKeyControlVerifier
{
    private readonly DidWebPinnedKeyControlChallengeVerifier _challenges;

    /// <summary>
    /// Pin the original and successor keys before checking successor-only publication.
    /// Both preapprovals and the verifier HTTPS audience must be independently owned.
    /// </summary>
    public DidWebPinnedRetiredKeyControlVerifier(
        string didIdentifier, Uri verifierAudience, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, TimeProvider timeProvider,
        int capacity = 1024, TimeSpan? lifetime = null)
    {
        // Test-only RED stub: the runtime retirement admission is not implemented.
        _challenges = new DidWebPinnedKeyControlChallengeVerifier(
            didIdentifier, "#key-2", verifierAudience,
            pinnedSuccessorPublicKey, timeProvider, capacity, lifetime);
    }

    /// <summary>Issue unpredictable verifier-owned one-use signing bytes.</summary>
    public DidWebPinnedKeyControlChallenge Issue() => _challenges.Issue();

    /// <summary>
    /// Check exact live successor-only publication and the real successor signature
    /// before atomically consuming the original nonce.
    /// </summary>
    public Task<bool> TryVerifyAndConsumeAsync(
        byte[] nonce, byte[] signature, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("RED: successor-only published key-control admission is not implemented.");

    /// <summary>Use a public-IP-only isolated HTTPS transport.</summary>
    public Task<bool> TryVerifyAndConsumeWithIsolatedTransportAsync(
        byte[] nonce, byte[] signature, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("RED: successor-only published key-control admission is not implemented.");
}
