using System.Security.Cryptography;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Bounded process-local challenge storage for the development presentation profile.</summary>
/// <remarks>Register as a singleton. Restart invalidates outstanding requests. Multiple instances require a shared atomic store.</remarks>
public sealed class InMemoryPresentationChallengeStore : IPresentationChallengeStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;

    /// <summary>The longest supported challenge and presentation lifetime.</summary>
    public static TimeSpan MaximumLifetime => TimeSpan.FromMinutes(5);

    /// <summary>Creates a store with an injectable clock and an outstanding-request limit.</summary>
    public InMemoryPresentationChallengeStore(TimeProvider timeProvider, int capacity = 1024)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _timeProvider = timeProvider;
        _capacity = capacity;
    }

    /// <inheritdoc />
    public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
    {
        if (verifierTenantId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty verifier tenant is required.", nameof(verifierTenantId));
        }

        ValidateIdentifier(audience, nameof(audience));
        ValidateIdentifier(trustedIssuerDid, nameof(trustedIssuerDid));
        var duration = lifetime ?? TimeSpan.FromMinutes(2);
        if (duration < TimeSpan.FromSeconds(1) || duration > MaximumLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Challenge lifetime must be between one second and five minutes.");
        }

        lock (_gate)
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var expired in _entries.Where(entry => entry.Value.Challenge.ExpiresAt <= now).Select(entry => entry.Key).ToArray())
            {
                _entries.Remove(expired);
            }

            if (_entries.Count >= _capacity)
            {
                throw new InvalidOperationException("The outstanding presentation challenge limit has been reached.");
            }

            string nonce;
            do
            {
                nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            }
            while (_entries.ContainsKey(nonce));

            var challenge = new PresentationChallenge
            {
                Nonce = nonce,
                Audience = audience,
                TrustedIssuerDid = trustedIssuerDid,
                ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(now.Add(duration).ToUnixTimeSeconds())
            };
            _entries.Add(nonce, new Entry(verifierTenantId, challenge));
            return challenge;
        }
    }

    /// <inheritdoc />
    public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce)
    {
        lock (_gate)
        {
            return FindLive(verifierTenantId, audience, nonce);
        }
    }

    /// <inheritdoc />
    public bool TryConsume(Guid verifierTenantId, string audience, string nonce)
    {
        lock (_gate)
        {
            return FindLive(verifierTenantId, audience, nonce) != null && _entries.Remove(nonce);
        }
    }

    private PresentationChallenge? FindLive(Guid tenantId, string audience, string nonce)
    {
        if (tenantId == Guid.Empty || string.IsNullOrEmpty(nonce) || nonce.Length != 43 || !_entries.TryGetValue(nonce, out var entry))
        {
            return null;
        }

        if (entry.Challenge.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            _entries.Remove(nonce);
            return null;
        }

        return entry.TenantId == tenantId && string.Equals(entry.Challenge.Audience, audience, StringComparison.Ordinal)
            ? entry.Challenge : null;
    }

    private static void ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 2048)
        {
            throw new ArgumentException("Identifier exceeds the 2048-character limit.", parameterName);
        }
    }

    private sealed record Entry(Guid TenantId, PresentationChallenge Challenge);
}
