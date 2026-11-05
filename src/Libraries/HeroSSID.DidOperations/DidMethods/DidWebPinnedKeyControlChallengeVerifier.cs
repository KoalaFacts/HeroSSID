namespace HeroSSID.DidOperations.DidMethods;

/// <summary>A verifier-owned, single-use did:web key-control challenge.</summary>
public sealed class DidWebPinnedKeyControlChallenge
{
    internal DidWebPinnedKeyControlChallenge(
        byte[] nonce, byte[] signingInput, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        throw new NotSupportedException("Challenge issuance is not implemented.");
    }

    /// <summary>The random challenge nonce; callers receive a defensive copy.</summary>
    public byte[] Nonce => throw new NotSupportedException();

    /// <summary>Exact bytes the externally controlled Ed25519 key must sign.</summary>
    public byte[] SigningInput => throw new NotSupportedException();

    /// <summary>Verifier-owned issuance instant.</summary>
    public DateTimeOffset IssuedAt => throw new NotSupportedException();

    /// <summary>Verifier-owned expiration instant.</summary>
    public DateTimeOffset ExpiresAt => throw new NotSupportedException();
}

/// <summary>
/// A process-local verifier that issues bounded challenges, checks independent
/// Ed25519 private-key possession, and consumes each valid challenge only once.
/// This does not enroll a DID or grant identity, issuer trust or authorization.
/// </summary>
public sealed class DidWebPinnedKeyControlChallengeVerifier
{
    /// <summary>Create a verifier using independently approved did:web, method, audience and public key.</summary>
    public DidWebPinnedKeyControlChallengeVerifier(
        string didIdentifier, string methodFragment, Uri verifierAudience,
        byte[] pinnedPublicKey, TimeProvider timeProvider, int capacity = 1024,
        TimeSpan? lifetime = null)
    {
        throw new NotSupportedException("Challenge store is not implemented.");
    }

    /// <summary>Create a fresh, short-lived challenge or reject exhausted capacity.</summary>
    public DidWebPinnedKeyControlChallenge Issue() => throw new NotSupportedException();

    /// <summary>Verify a genuine signature and atomically consume its challenge on success.</summary>
    public bool TryVerifyAndConsume(byte[] nonce, byte[] signature) =>
        throw new NotSupportedException();
}
