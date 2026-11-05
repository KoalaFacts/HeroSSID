using System.Security.Cryptography;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>A verifier-owned, single-use did:web key-control challenge.</summary>
public sealed class DidWebPinnedKeyControlChallenge
{
    private readonly byte[] _nonce;
    private readonly byte[] _signingInput;

    internal DidWebPinnedKeyControlChallenge(
        byte[] nonce, byte[] signingInput, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        _nonce = (byte[])nonce.Clone();
        _signingInput = (byte[])signingInput.Clone();
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>Return a defensive copy of the unpredictable verifier-owned nonce.</summary>
    public byte[] GetNonce() => (byte[])_nonce.Clone();

    /// <summary>
    /// Return a defensive copy of exact bytes to sign at the independently
    /// controlled Ed25519 signer. No private key enters the verifier.
    /// </summary>
    public byte[] GetSigningInput() => (byte[])_signingInput.Clone();

    /// <summary>The issuance instant retained by the verifier.</summary>
    public DateTimeOffset IssuedAt { get; }

    /// <summary>The expiry instant retained by the verifier.</summary>
    public DateTimeOffset ExpiresAt { get; }
}

/// <summary>
/// Bounded single-process verification of genuine Ed25519 control over an
/// independently pinned did:web verification key. Valid signatures atomically
/// consume their unpredictable nonce; forged proofs never consume a challenge.
/// </summary>
/// <remarks>
/// Register as a singleton per verifier policy. Process restart invalidates
/// outstanding challenges. Replicated verifiers require a shared atomic store.
/// Key control is not domain ownership, issuer enrollment, identity verification
/// or authorization to act on behalf of any person, organisation or agent.
/// </remarks>
public sealed class DidWebPinnedKeyControlChallengeVerifier
{
    private static readonly TimeSpan s_maximumLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan s_defaultLifetime = TimeSpan.FromMinutes(2);
    private readonly object _gate = new();
    private readonly Dictionary<string, ChallengeWindow> _entries = new(StringComparer.Ordinal);
    private readonly string _didIdentifier;
    private readonly string _methodFragment;
    private readonly Uri _verifierAudience;
    private readonly byte[] _pinnedPublicKey;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _lifetime;
    private readonly int _capacity;

    /// <summary>
    /// Create a process-local verifier with an independently enrolled did:web
    /// DID, method, HTTPS verifier audience and 32-byte Ed25519 public key.
    /// No remote DID resolution or automatic trust enrollment is performed.
    /// </summary>
    public DidWebPinnedKeyControlChallengeVerifier(
        string didIdentifier, string methodFragment, Uri verifierAudience,
        byte[] pinnedPublicKey, TimeProvider timeProvider, int capacity = 1024,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(pinnedPublicKey);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if (capacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity),
                "Capacity must be between one and 4096 pending challenges.");
        }

        TimeSpan acceptedLifetime = lifetime ?? s_defaultLifetime;
        if (acceptedLifetime <= TimeSpan.Zero || acceptedLifetime > s_maximumLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime),
                "Challenge lifetime must be positive and at most five minutes.");
        }

        // Validate DID/method/audience through the exact signing profile before
        // issuing any challenge. The placeholder bytes are not a live nonce.
        DidWebPinnedKeyControlProof.CreateSigningInput(
            didIdentifier, methodFragment, verifierAudience, new byte[32],
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.Add(acceptedLifetime));

        if (pinnedPublicKey.Length != 32 ||
            pinnedPublicKey.All(static value => value == 0) ||
            !PublicKey.TryImport(SignatureAlgorithm.Ed25519, pinnedPublicKey,
                KeyBlobFormat.RawPublicKey, out _))
        {
            throw new ArgumentException(
                "An independently approved valid Ed25519 public key is required.",
                nameof(pinnedPublicKey));
        }

        _didIdentifier = didIdentifier;
        _methodFragment = methodFragment;
        _verifierAudience = verifierAudience;
        _pinnedPublicKey = (byte[])pinnedPublicKey.Clone();
        _timeProvider = timeProvider;
        _capacity = capacity;
        _lifetime = acceptedLifetime;
    }

    /// <summary>
    /// Create an unpredictable, one-use challenge with exact signer bytes.
    /// Reject new issuance when the bounded pending capacity is exhausted.
    /// </summary>
    public DidWebPinnedKeyControlChallenge Issue()
    {
        lock (_gate)
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            long timestamp = _timeProvider.GetTimestamp();
            foreach (string expired in _entries
                .Where(entry => IsExpired(entry.Value, now, timestamp))
                .Select(entry => entry.Key).ToArray())
            {
                _entries.Remove(expired);
            }

            if (_entries.Count >= _capacity)
            {
                throw new InvalidOperationException(
                    "The outstanding did:web key-control challenge limit has been reached.");
            }

            byte[] nonce;
            string nonceKey;
            do
            {
                nonce = RandomNumberGenerator.GetBytes(32);
                nonceKey = Convert.ToHexString(nonce);
            }
            while (_entries.ContainsKey(nonceKey));

            DateTimeOffset expiresAt = now.Add(_lifetime);
            byte[] signingInput = DidWebPinnedKeyControlProof.CreateSigningInput(
                _didIdentifier, _methodFragment, _verifierAudience, nonce, now, expiresAt);

            _entries.Add(nonceKey, new ChallengeWindow(now, expiresAt, timestamp));
            return new DidWebPinnedKeyControlChallenge(nonce, signingInput, now, expiresAt);
        }
    }

    /// <summary>
    /// Verify an externally created Ed25519 signature and atomically remove the
    /// exact live challenge. Invalid signatures, unknown nonces and expired
    /// challenges fail without releasing issuer trust or authorizing any action.
    /// </summary>
    public bool TryVerifyAndConsume(byte[] nonce, byte[] signature)
    {
        if (nonce is null || nonce.Length != 32 ||
            signature is null || signature.Length != 64)
        {
            return false;
        }

        // The caller owns its input buffer and can mutate it while waiting for
        // _gate. Keep lookup, verification and removal bound to one snapshot.
        byte[] nonceSnapshot = (byte[])nonce.Clone();
        string nonceKey = Convert.ToHexString(nonceSnapshot);
        lock (_gate)
        {
            if (!_entries.TryGetValue(nonceKey, out ChallengeWindow? window))
            {
                return false;
            }

            DateTimeOffset now = _timeProvider.GetUtcNow();
            long timestamp = _timeProvider.GetTimestamp();
            if (IsExpired(window, now, timestamp))
            {
                _entries.Remove(nonceKey);
                return false;
            }

            if (now < window.IssuedAt ||
                !DidWebPinnedKeyControlProof.TryVerify(
                    _didIdentifier, _methodFragment, _verifierAudience, nonceSnapshot,
                    window.IssuedAt, window.ExpiresAt, now, _pinnedPublicKey, signature))
            {
                return false;
            }

            // Lock covers both verification and removal: only one concurrent
            // submitter can ever receive a true result for this verifier.
            return _entries.Remove(nonceKey);
        }
    }

    // UTC is still signed and checked, but wall-clock corrections must never
    // lengthen a live nonce. The TimeProvider timestamp is elapsed-time based.
    private bool IsExpired(ChallengeWindow window, DateTimeOffset now, long timestamp) =>
        now >= window.ExpiresAt ||
        timestamp < window.IssuedTimestamp ||
        _timeProvider.GetElapsedTime(window.IssuedTimestamp, timestamp) >= _lifetime;

    private sealed record ChallengeWindow(
        DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, long IssuedTimestamp);
}
