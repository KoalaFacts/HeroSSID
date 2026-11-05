using System;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Verifier-pinned proof that an operator controls the private key corresponding
/// to a published did:web Ed25519 verification method. No identity, authority,
/// issuer trust, domain ownership or replay-store decision is implied.
/// </summary>
public static class DidWebPinnedKeyControlProof
{
    /// <summary>
    /// Construct a purpose- and audience-separated challenge for an independently
    /// operating Ed25519 signer. The verifier owns the fresh nonce and its lifecycle.
    /// </summary>
    public static byte[] CreateSigningInput(string didIdentifier, string methodFragment,
        Uri verifierAudience, byte[] nonce, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
        => throw new NotSupportedException("Test-first: key-control signing input is not implemented.");

    /// <summary>
    /// Check an actual Ed25519 signature using the verifier's independently pinned
    /// public key. The verifier separately consumes the nonce atomically.
    /// </summary>
    public static bool TryVerify(string didIdentifier, string methodFragment,
        Uri verifierAudience, byte[] nonce, DateTimeOffset issuedAt, DateTimeOffset expiresAt,
        DateTimeOffset now, byte[] pinnedPublicKey, byte[] signature)
        => throw new NotSupportedException("Test-first: pinned key-control verification is not implemented.");
}
