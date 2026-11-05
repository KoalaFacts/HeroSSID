namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Independently pinned successor-only did:web HTTPS publication plus one-use
/// successor Ed25519 key-control admission. This does not establish DID/domain
/// ownership, issuer trust, identity or authorization.
/// </summary>
/// <remarks>
/// Use one long-lived instance per operator-approved DID, old/successor key
/// pair and verifier audience. This bounded process-local nonce store is not
/// suitable for replicated verifiers without an external atomic replay barrier.
/// </remarks>
public sealed class DidWebPinnedRetiredKeyControlVerifier
{
    private readonly DidWebPinnedKeyControlChallengeVerifier _challenges;
    private readonly string _didIdentifier;
    private readonly byte[] _pinnedOldPublicKey;
    private readonly byte[] _pinnedSuccessorPublicKey;

    /// <summary>
    /// Independently preapprove both keys and the verifier HTTPS audience.
    /// The exact successor-only DID document must retain #key-2, remove #key-1,
    /// and contain no extra methods, authentication or assertion relationships.
    /// </summary>
    public DidWebPinnedRetiredKeyControlVerifier(
        string didIdentifier, Uri verifierAudience, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, TimeProvider timeProvider,
        int capacity = 1024, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedSuccessorPublicKey);

        // Validate independent, distinct old and successor pins before
        // allocating the challenge store. No key is taken from a remote DID.
        _ = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            didIdentifier, pinnedOldPublicKey, pinnedSuccessorPublicKey);
        _challenges = new DidWebPinnedKeyControlChallengeVerifier(
            didIdentifier, "#key-2", verifierAudience,
            pinnedSuccessorPublicKey, timeProvider, capacity, lifetime);
        _didIdentifier = didIdentifier;
        _pinnedOldPublicKey = (byte[])pinnedOldPublicKey.Clone();
        _pinnedSuccessorPublicKey = (byte[])pinnedSuccessorPublicKey.Clone();
    }

    /// <summary>
    /// Issue exact random signing bytes for the independent successor signer.
    /// No private key ever enters the verifier.
    /// </summary>
    public DidWebPinnedKeyControlChallenge Issue() => _challenges.Issue();

    /// <summary>
    /// Require a bounded exact HTTPS successor-only DID document and a genuine
    /// #key-2 signature over the verifier's original live nonce. The challenge
    /// is atomically consumed only if both independent checks pass.
    /// </summary>
    /// <remarks>
    /// Use a dedicated credential-free, no-redirect/no-proxy HttpClient, or
    /// the isolated transport overload. Caller must authenticate, rate-limit
    /// and independently authorize the operation; HTTPS GET is performed before
    /// signature verification. HTTP failure does not consume a challenge.
    /// This only establishes a point-in-time publication and signing result.
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

        // Do not let caller-owned buffers change while an HTTPS request awaits.
        // Both the live verifier challenge and independent signature must
        // remain bound to the exact bytes provided at entry.
        byte[] nonceSnapshot = (byte[])nonce.Clone();
        byte[] signatureSnapshot = (byte[])signature.Clone();

        bool published = await DidWebPinnedKeyRetirement.FetchAndMatchAsync(
            _didIdentifier, _pinnedOldPublicKey, _pinnedSuccessorPublicKey,
            http, maximumDuration, cancellationToken).ConfigureAwait(false);
        if (!published)
        {
            return false;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return _challenges.TryVerifyAndConsume(nonceSnapshot, signatureSnapshot);
    }

    /// <summary>
    /// Use an ephemeral public-IP-only, non-redirecting, credential-free HTTPS
    /// transport with normal hostname TLS validation and no proxy/cookies.
    /// Network egress rules and independently approved key policy are still
    /// required at the deployment boundary.
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
