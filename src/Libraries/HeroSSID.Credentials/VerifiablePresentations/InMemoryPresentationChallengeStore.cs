using System.Security.Cryptography;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Bounded process-local challenge storage for the development presentation profile.</summary>
/// <remarks>Register as a singleton. Restart invalidates requests. Multiple replicas require a shared atomic store.</remarks>
public sealed class InMemoryPresentationChallengeStore : IPresentationChallengeStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;
    private readonly int _tenantCapacity;

    /// <summary>The longest supported challenge and presentation lifetime.</summary>
    public static TimeSpan MaximumLifetime => TimeSpan.FromMinutes(5);

    /// <summary>Configures outstanding-request limits; the default per-tenant ceiling is 128, capped by global capacity.</summary>
    public InMemoryPresentationChallengeStore(TimeProvider timeProvider, int capacity = 1024, int? tenantCapacity = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _tenantCapacity = PresentationChallengePolicy.TenantCapacity(capacity, tenantCapacity);
        _timeProvider = timeProvider;
        _capacity = capacity;
    }

    /// <inheritdoc />
    public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
    {
        var duration = PresentationChallengePolicy.Validate(verifierTenantId, audience, trustedIssuerDid, lifetime);
        lock (_gate)
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var expired in _entries.Where(entry => entry.Value.Challenge.ExpiresAt <= now).Select(entry => entry.Key).ToArray())
            {
                _entries.Remove(expired);
            }

            if (_entries.Count >= _capacity || _entries.Values.Count(entry => entry.TenantId == verifierTenantId) >= _tenantCapacity)
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
                Nonce = nonce, Audience = audience, TrustedIssuerDid = trustedIssuerDid,
                ExpiresAt = PresentationChallengePolicy.Expiry(now, duration)
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
        if (!PresentationChallengePolicy.IsValidLookup(tenantId, audience, nonce) || !_entries.TryGetValue(nonce, out var entry))
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

    private sealed record Entry(Guid TenantId, PresentationChallenge Challenge);
}
