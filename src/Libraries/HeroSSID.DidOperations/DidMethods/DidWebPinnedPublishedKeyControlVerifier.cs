namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Operator-pinned, single-process admission requiring BOTH a live canonical
/// HTTPS DID publication and an independently signed one-use Ed25519 proof.
/// No issuer trust, domain ownership, identity or authorization is conferred.
/// </summary>
/// <remarks>
/// Use one long-lived instance per preapproved DID/key/verifier-audience policy.
/// This process-local challenge store is not safe for replicated verifiers.
/// The exact one-key DID document profile requires the #key-1 method; transition
/// overlap and successor-only #key-2 retirement require different profiles.
/// </remarks>
public sealed class DidWebPinnedPublishedKeyControlVerifier
{
    private readonly DidWebPinnedKeyControlChallengeVerifier _challenges;
    private readonly string _didIdentifier;
    private readonly byte[] _pinnedPublicKey;

    /// <summary>
    /// Pin the verifier-approved DID, Ed25519 public key, and HTTPS audience
    /// independently of the signer and remotely published DID document.
    /// </summary>
    public DidWebPinnedPublishedKeyControlVerifier(
        string didIdentifier, Uri verifierAudience, byte[] pinnedPublicKey,
        TimeProvider timeProvider, int capacity = 1024, TimeSpan? lifetime = null)
    {
        // The underlying verifier validates the DID, method, audience, key,
        // time source, bounded capacity and five-minute maximum lifetime.
        _challenges = new DidWebPinnedKeyControlChallengeVerifier(
            didIdentifier, "#key-1", verifierAudience,
            pinnedPublicKey, timeProvider, capacity, lifetime);
        _didIdentifier = didIdentifier;
        _pinnedPublicKey = (byte[])pinnedPublicKey.Clone();
    }

    /// <summary>
    /// Issue the random, one-use exact signer bytes to the external Ed25519
    /// key holder without ever taking custody of its private key.
    /// </summary>
    public DidWebPinnedKeyControlChallenge Issue() => _challenges.Issue();

    /// <summary>
    /// Fail closed unless the canonical HTTPS DID document matches the pinned
    /// one-key profile and the genuine signer response passes the original
    /// verifier-bound challenge. Consume only after BOTH checks succeed.
    /// </summary>
    /// <remarks>
    /// The injected HttpClient must have no credentials, redirects, cookies or
    /// proxy; use the isolated-transport overload in production by default.
    /// Invalid submissions can still cause a bounded HTTPS GET: enforce
    /// caller authentication and rate limits before this method. A successful
    /// result proves only matching publication and one-use private-key control.
    /// </remarks>
    public async Task<bool> TryVerifyAndConsumeAsync(
        byte[] nonce, byte[] signature, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        if (nonce is null || nonce.Length != 32 ||
            signature is null || signature.Length != 64)
        {
            return false;
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Bind this invocation to the exact proof bytes received at entry.
        // The caller retains both arrays and an awaited HTTPS request can give
        // it time to replace an initially forged nonce or signature with valid
        // bytes. Never verify or consume a different proof after that await.
        byte[] nonceSnapshot = (byte[])nonce.Clone();
        byte[] signatureSnapshot = (byte[])signature.Clone();

        // Do not burn the live challenge if public publication is unavailable,
        // stale, hostile, redirected or substituted. The existing fetch path
        // bounds the body, duration and document profile.
        bool published = await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            _didIdentifier, _pinnedPublicKey, http, maximumDuration,
            cancellationToken).ConfigureAwait(false);
        if (!published)
        {
            return false;
        }

        cancellationToken.ThrowIfCancellationRequested();
        // The signer signature binds the original verifier DID, audience,
        // issuance/expiry and unpredictable nonce; atomically consume once.
        return _challenges.TryVerifyAndConsume(nonceSnapshot, signatureSnapshot);
    }

    /// <summary>
    /// Use an ephemeral no-proxy, no-redirect, no-cookie, credential-free HTTPS
    /// handler with pre-TCP public-IP/DNS checks and normal hostname TLS.
    /// Operators still enforce their own network egress and trust policy.
    /// </summary>
    public async Task<bool> TryVerifyAndConsumeWithIsolatedTransportAsync(
        byte[] nonce, byte[] signature, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = DidWebPinnedDocumentHttpTransport.CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler, disposeHandler: false);
        return await TryVerifyAndConsumeAsync(nonce, signature, http,
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }
}
