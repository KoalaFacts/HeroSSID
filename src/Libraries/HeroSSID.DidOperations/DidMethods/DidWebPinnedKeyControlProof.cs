using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Verifier-pinned evidence that an independently operated signer controls the
/// Ed25519 private key for a preapproved did:web verification method. This
/// does not enroll trust, verify a real-world identity or authorize an action.
/// </summary>
public static class DidWebPinnedKeyControlProof
{
    private const string Purpose = "HeroSSID/did:web/pinned-key-possession/v1";
    private static readonly TimeSpan s_maximumLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Create deterministic, domain-separated signing bytes for a verifier-owned
    /// unpredictable nonce. A private-key holder signs the returned bytes at
    /// its own boundary; the verifier must retain and atomically consume the
    /// nonce in a separate one-use challenge store.
    /// </summary>
    public static byte[] CreateSigningInput(
        string didIdentifier, string methodFragment, Uri verifierAudience,
        byte[] nonce, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(methodFragment);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(nonce);

        if (!new DidWebMethod().IsValid(didIdentifier))
        {
            throw new ArgumentException(
                "The DID must use the canonical, supported did:web profile.",
                nameof(didIdentifier));
        }

        if (methodFragment is not ("#key-1" or "#key-2"))
        {
            throw new ArgumentException(
                "Only a separately pinned #key-1 or #key-2 method is supported.",
                nameof(methodFragment));
        }

        if (!verifierAudience.IsAbsoluteUri ||
            !string.Equals(verifierAudience.Scheme, Uri.UriSchemeHttps,
                StringComparison.Ordinal) ||
            verifierAudience.HostNameType != UriHostNameType.Dns ||
            verifierAudience.IsLoopback ||
            !string.IsNullOrEmpty(verifierAudience.UserInfo) ||
            !string.IsNullOrEmpty(verifierAudience.Fragment) ||
            verifierAudience.AbsoluteUri.Length > 2_048)
        {
            throw new ArgumentException(
                "The verifier audience must be a bounded absolute HTTPS DNS URI without credentials or fragment.",
                nameof(verifierAudience));
        }

        if (nonce.Length != 32)
        {
            throw new ArgumentException(
                "A verifier-generated 32-byte nonce is required.", nameof(nonce));
        }

        TimeSpan lifetime = expiresAt - issuedAt;
        if (lifetime <= TimeSpan.Zero || lifetime > s_maximumLifetime)
        {
            throw new ArgumentException(
                "The challenge must have a positive lifetime of at most five minutes.",
                nameof(expiresAt));
        }

        // A JSON array gives unambiguous field boundaries and a stable signing
        // representation. UTC round-trip timestamps preserve subsecond ticks;
        // no untrusted token header, remote DID key or caller-supplied purpose
        // can change what the verifier is asking the independent signer to sign.
        return JsonSerializer.SerializeToUtf8Bytes(
            new[]
            {
                Purpose,
                didIdentifier,
                methodFragment,
                verifierAudience.AbsoluteUri,
                Convert.ToBase64String(nonce),
                issuedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                expiresAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
            });
    }

    /// <summary>
    /// Check the genuine Ed25519 signature against the independently pinned
    /// public key and the verifier's exact challenge. This only checks evidence:
    /// caller-controlled atomic nonce consumption and policy approval are
    /// mandatory before accepting or trusting a key transition.
    /// </summary>
    public static bool TryVerify(
        string didIdentifier, string methodFragment, Uri verifierAudience,
        byte[] nonce, DateTimeOffset issuedAt, DateTimeOffset expiresAt,
        DateTimeOffset now, byte[] pinnedPublicKey, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(pinnedPublicKey);
        ArgumentNullException.ThrowIfNull(signature);

        if (pinnedPublicKey.Length != 32 || signature.Length != 64 ||
            now < issuedAt || now >= expiresAt)
        {
            return false;
        }

        try
        {
            byte[] input = CreateSigningInput(didIdentifier, methodFragment,
                verifierAudience, nonce, issuedAt, expiresAt);
            using PublicKey publicKey = PublicKey.Import(
                SignatureAlgorithm.Ed25519, pinnedPublicKey, KeyBlobFormat.RawPublicKey);
            return SignatureAlgorithm.Ed25519.Verify(publicKey, input, signature);
        }
        catch (ArgumentException)
        {
            // Invalid challenge, malformed public key or invalid method input.
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
