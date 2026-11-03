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
    private readonly Dictionary<string, DateTimeOffset> _reservations = new(StringComparer.Ordinal);

    /// <summary>
    /// Reserve an opaque reference before issuing a durable verifier challenge.
    /// A full volatile host rejects the request without using any PostgreSQL
    /// challenge rows. A 5-minute lease prevents indefinite abandoned slots.
    /// </summary>
    public string Reserve()
    {
        lock (_gate)
        {
            RemoveExpired(clock.GetUtcNow());
            if (_entries.Count + _reservations.Count >= MaximumEntries)
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
            while (_entries.ContainsKey(token) || _reservations.ContainsKey(token));

            _reservations.Add(token, clock.GetUtcNow().AddMinutes(5));
            return token;
        }
    }

    /// <summary>
    /// Release an uncommitted reservation after an issuance/signing failure.
    /// Already published entries are deliberately not removed.
    /// </summary>
    public void ReleaseReservation(string opaqueReference)
    {
        lock (_gate)
        {
            _reservations.Remove(opaqueReference);
        }
    }

    /// <summary>
    /// Reclaim volatile Request Objects for an exact challenge after the authorized
    /// verifier atomically cancels that challenge in the independent challenge store.
    /// This is scoped to tenant, client audience and nonce; it cannot release a
    /// pending request belonging to another challenge. No durable storage changes.
    /// </summary>
    public void RetireConsumedChallenge(Guid tenantId, string audience, string nonce)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A tenant is required.", nameof(tenantId));
        }

        lock (_gate)
        {
            foreach (string reference in _entries
                .Where(entry => entry.Value.TenantId == tenantId &&
                    string.Equals(entry.Value.Audience, audience, StringComparison.Ordinal) &&
                    string.Equals(entry.Value.Nonce, nonce, StringComparison.Ordinal))
                .Select(entry => entry.Key).ToArray())
            {
                _entries.Remove(reference);
            }
        }
    }

    /// <summary>
    /// Verify the original Ed25519 Request Object and live tenant-owned challenge
    /// before publishing exact JWT bytes behind an unpredictable reference.
    /// This does not establish an application's trusted public HTTPS URL.
    /// </summary>
    public string Publish(Guid tenantId, string signedRequestJwt, string trustedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri)
    {
        string reference = Reserve();
        try
        {
            PublishReserved(reference, tenantId, signedRequestJwt, trustedVerifierDid,
                expectedResponseUri, expectedCredentialType, expectedSubjectContextUri);
            return reference;
        }
        finally
        {
            ReleaseReservation(reference);
        }
    }

    /// <summary>
    /// Commit an already reserved reference after signing and original challenge
    /// validation. Only the owner of this single-process store may publish.
    /// </summary>
    public void PublishReserved(string opaqueReference, Guid tenantId,
        string signedRequestJwt, string trustedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri)
    {
        ArgumentNullException.ThrowIfNull(signedRequestJwt);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        if (tenantId == Guid.Empty ||
            !OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(signedRequestJwt,
                trustedVerifierDid, expectedResponseUri, expectedCredentialType,
                expectedSubjectContextUri, clock, out var signed) || signed is null ||
            !HostedPresentationChallengeNonce.IsHosted(signed.Challenge.Nonce))
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
            if (!_reservations.TryGetValue(opaqueReference, out DateTimeOffset reservationExpiry) ||
                reservationExpiry <= clock.GetUtcNow())
            {
                throw new InvalidOperationException(
                    "The request object reservation expired before publication.");
            }

            _reservations.Remove(opaqueReference);
            _entries.Add(opaqueReference, new HostedRequest(tenantId, signed.ClientId,
                signed.Challenge.Nonce, signed.Challenge.TrustedIssuerDid,
                signed.Challenge.ExpiresAt, signedRequestJwt, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri));
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

    /// <summary>
    /// Detect any matching retained publication, including duplicate/ambiguous
    /// originals. The legacy unbound verifier must reject such challenges
    /// rather than interpreting strict lookup failure as a license to downgrade.
    /// This conservative guard does not depend on a potentially already-spent
    /// challenge row. Volatile single-process only.
    /// </summary>
    public bool HasPublishedChallenge(Guid tenantId, string audience, string nonce)
    {
        if (!PresentationChallengePolicy.IsValidLookup(tenantId, audience, nonce))
        {
            return false;
        }

        lock (_gate)
        {
            RemoveExpired(clock.GetUtcNow());
            return _entries.Values.Any(entry =>
                entry.TenantId == tenantId &&
                string.Equals(entry.Audience, audience, StringComparison.Ordinal) &&
                string.Equals(entry.Nonce, nonce, StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// Locate the original *server-published* verifier request by its exact
    /// tenant/client/nonce, for a strict authenticated verification route.
    /// No reference, request hash, callback or policy comes from the holder.
    /// Multiple publications for one challenge fail closed rather than choosing
    /// an arbitrary Request Object. Volatile single-process storage only.
    /// </summary>
    public bool TryFindPublishedChallenge(Guid tenantId, string audience, string nonce,
        out HostedVerifierRequest? request)
    {
        request = null;
        if (!PresentationChallengePolicy.IsValidLookup(tenantId, audience, nonce))
        {
            return false;
        }

        HostedRequest[] matches;
        lock (_gate)
        {
            RemoveExpired(clock.GetUtcNow());
            matches = _entries.Values
                .Where(entry => entry.TenantId == tenantId &&
                    string.Equals(entry.Audience, audience, StringComparison.Ordinal) &&
                    string.Equals(entry.Nonce, nonce, StringComparison.Ordinal))
                .Take(2).ToArray();
        }

        if (matches.Length != 1)
        {
            return false;
        }

        HostedRequest hosted = matches[0];
        PresentationChallenge? retained = challenges.Find(
            tenantId, hosted.Audience, hosted.Nonce);
        if (retained is null || retained.ExpiresAt != hosted.ExpiresAt ||
            !string.Equals(retained.TrustedIssuerDid, hosted.TrustedIssuerDid,
                StringComparison.Ordinal))
        {
            return false;
        }

        request = new HostedVerifierRequest(hosted.SignedRequestJwt,
            hosted.ResponseUri, hosted.CredentialType, hosted.SubjectContextUri);
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

        foreach (string token in _reservations
            .Where(entry => entry.Value <= now)
            .Select(entry => entry.Key).ToArray())
        {
            _reservations.Remove(token);
        }
    }

    private sealed record HostedRequest(
        Guid TenantId, string Audience, string Nonce,
        string TrustedIssuerDid, DateTimeOffset ExpiresAt, string SignedRequestJwt,
        Uri ResponseUri, string CredentialType, Uri SubjectContextUri);
}

/// <summary>Original server-authenticated, volatile verifier request metadata.</summary>
public sealed record HostedVerifierRequest(
    string SignedRequestJwt, Uri ResponseUri, string CredentialType, Uri SubjectContextUri);
