namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Operator-pinned, one-process admission combining a live exact HTTPS DID
/// publication check with an independently signed one-use key-control challenge.
/// This is evidence only, not issuer trust, domain ownership or authorization.
/// </summary>
public sealed class DidWebPinnedPublishedKeyControlVerifier
{
    private readonly DidWebPinnedKeyControlChallengeVerifier _challenges;

    public DidWebPinnedPublishedKeyControlVerifier(
        string didIdentifier, Uri verifierAudience, byte[] pinnedPublicKey,
        TimeProvider timeProvider, int capacity = 1024, TimeSpan? lifetime = null)
    {
        _challenges = new DidWebPinnedKeyControlChallengeVerifier(
            didIdentifier, "#key-1", verifierAudience,
            pinnedPublicKey, timeProvider, capacity, lifetime);
    }

    /// <summary>Issue a verifier-owned random challenge to the separate signer.</summary>
    public DidWebPinnedKeyControlChallenge Issue() => _challenges.Issue();

    /// <summary>
    /// Require both a live matching, pre-pinned did:web publication and the
    /// genuine Ed25519 signature; only then atomically consume the challenge.
    /// The HttpClient must use a dedicated credential-free no-redirect transport.
    /// </summary>
    public Task<bool> TryVerifyAndConsumeAsync(
        byte[] nonce, byte[] signature, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Published one-use key admission is not implemented.");

    /// <summary>Use an isolated public-only HTTPS handler for production egress.</summary>
    public Task<bool> TryVerifyAndConsumeWithIsolatedTransportAsync(
        byte[] nonce, byte[] signature, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Published one-use key admission is not implemented.");
}
