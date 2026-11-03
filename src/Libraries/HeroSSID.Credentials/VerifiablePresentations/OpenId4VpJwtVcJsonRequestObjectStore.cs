using System.Security.Cryptography;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Bounded volatile storage for original signed OpenID4VP Request Objects.
/// This store is explicitly single-process, not shared or durable: operators
/// must route a by-reference GET back to the publishing instance.
/// </summary>
public sealed class OpenId4VpJwtVcJsonRequestObjectStore(
    IPresentationChallengeStore challenges, TimeProvider clock)
{
    private const int MaximumEntries = 256;
    private readonly object _gate = new();
    private readonly Dictionary<string, HostedRequest> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Verify the original Ed25519 Request Object and live tenant-owned challenge
    /// before publishing exact JWT bytes behind an unpredictable reference.
    /// This does not establish an application's trusted public HTTPS URL.
    /// </summary>
    public string Publish(Guid tenantId, string signedRequestJwt, string trustedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri)
    {
        ArgumentNullException.ThrowIfNull(signedRequestJwt);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        if (tenantId == Guid.Empty ||
            !OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(signedRequestJwt,
                trustedVerifierDid, expectedResponseUri, expectedCredentialType,
                expectedSubjectContextUri, clock, out var signed) || signed is null)
        {
            throw new ArgumentException(
                "An authentic live tenant-owned verifier request is required.",
                nameof(signedRequestJwt));
        }

        PresentationChallenge? retained = challenges.Find(
            tenantId, signed.ClientId, signed.Challenge.Nonce);
        if (retained is null ||
            retained.ExpiresAt != signed.Challenge.ExpiresAt ||
            !string.Equals(retained.TrustedIssuerDid,
                signed.Challenge.TrustedIssuerDid, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The signed verifier request does not match an outstanding tenant challenge.",
                nameof(signedRequestJwt));
        }

        lock (_gate)
        {
            RemoveExpired(clock.GetUtcNow());
            if (_entries.Count >= MaximumEntries)
            {
                throw new InvalidOperationException(
                    "The volatile request object capacity has been reached.");
            }

            string token;
            do
            {
                byte[] random = RandomNumberGenerator.GetBytes(32);
                token = Convert.ToBase64String(random).TrimEnd('=')
                    .Replace('+', '-').Replace('/', '_');
            }
            while (_entries.ContainsKey(token));

            _entries.Add(token, new HostedRequest(tenantId, signed.ClientId,
                signed.Challenge.Nonce, signed.Challenge.TrustedIssuerDid,
                signed.Challenge.ExpiresAt, signedRequestJwt));
            return token;
        }
    }

    /// <summary>
    /// Serve only while the original independently stored verifier challenge
    /// is live. Repeated GET is harmless: only the holder response atomically
    /// consumes that challenge. Returns no JWT on unknown, cancelled or expired
    /// references. Races with cancellation remain safe at final verification.
    /// </summary>
    public bool TryGet(string opaqueReference, out string signedRequestJwt)
    {
        signedRequestJwt = string.Empty;
        if (opaqueReference is not { Length: 43 } ||
            !opaqueReference.All(static value =>
                char.IsAsciiLetterOrDigit(value) || value is '-' or '_'))
        {
            return false;
        }

        HostedRequest? hosted;
        lock (_gate)
        {
            if (!_entries.TryGetValue(opaqueReference, out hosted))
            {
                return false;
            }

            if (hosted.ExpiresAt <= clock.GetUtcNow())
            {
                _entries.Remove(opaqueReference);
                return false;
            }
        }

        PresentationChallenge? retained = challenges.Find(
            hosted.TenantId, hosted.Audience, hosted.Nonce);
        if (retained is null ||
            retained.ExpiresAt != hosted.ExpiresAt ||
            !string.Equals(retained.TrustedIssuerDid, hosted.TrustedIssuerDid,
                StringComparison.Ordinal))
        {
            lock (_gate)
            {
                _entries.Remove(opaqueReference);
            }

            return false;
        }

        signedRequestJwt = hosted.SignedRequestJwt;
        return true;
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (string token in _entries
            .Where(entry => entry.Value.ExpiresAt <= now)
            .Select(entry => entry.Key).ToArray())
        {
            _entries.Remove(token);
        }
    }

    private sealed record HostedRequest(
        Guid TenantId, string Audience, string Nonce,
        string TrustedIssuerDid, DateTimeOffset ExpiresAt, string SignedRequestJwt);
}
