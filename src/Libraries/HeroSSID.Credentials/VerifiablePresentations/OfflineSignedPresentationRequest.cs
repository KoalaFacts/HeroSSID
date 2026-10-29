using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// A bounded, issuer-preserving HeroSSID signed verifier request for independently operated
/// holders. This is not an OpenID4VP Request Object, trust registry or consent mechanism.
/// </summary>
public static class OfflineSignedPresentationRequest
{
    private const int MaximumRequestLength = 16_384;
    private const string RequestHeader = "{\"alg\":\"EdDSA\",\"typ\":\"herossid-request+jwt\"}";

    /// <summary>
    /// Signs the verifier's already-issued and retained challenge with its own Ed25519 did:key.
    /// The signer must have issued the challenge in a verifier-owned atomic replay store.
    /// The supplied private seed remains the caller's responsibility to protect and clear.
    /// </summary>
    public static string Create(PresentationChallenge challenge, string verifierDid, byte[] verifierPrivateKey, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(verifierDid);
        ArgumentNullException.ThrowIfNull(verifierPrivateKey);
        ArgumentNullException.ThrowIfNull(clock);

        var now = clock.GetUtcNow();
        if (verifierDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(verifierDid, out var verifierPublicKey))
        {
            throw new ArgumentException("The verifier must have a self-certifying Ed25519 did:key.", nameof(verifierDid));
        }

        if (verifierPrivateKey.Length != 32 || verifierPrivateKey.All(static value => value == 0))
        {
            throw new ArgumentException("A nonzero 32-byte verifier Ed25519 seed is required.", nameof(verifierPrivateKey));
        }

        if (string.IsNullOrWhiteSpace(challenge.Audience) ||
            challenge.Audience.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            string.IsNullOrWhiteSpace(challenge.TrustedIssuerDid) ||
            challenge.TrustedIssuerDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(challenge.TrustedIssuerDid, out _) ||
            !PresentationChallengePolicy.IsValidNonce(challenge.Nonce) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("An unexpired, bounded verifier challenge and did:key issuer are required.", nameof(challenge));
        }

        string payload = JsonSerializer.Serialize(new
        {
            iss = verifierDid,
            aud = challenge.Audience,
            nonce = challenge.Nonce,
            trustedIssuerDid = challenge.TrustedIssuerDid,
            iat = PresentationChallengePolicy.NumericDate(now),
            exp = PresentationChallengePolicy.NumericDate(challenge.ExpiresAt)
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(RequestHeader, payload, verifierPrivateKey);
        if (signed.Length > MaximumRequestLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, verifierPublicKey))
        {
            throw new ArgumentException("The signing seed does not control the verifier DID or request exceeds its limit.", nameof(verifierPrivateKey));
        }

        if (challenge.ExpiresAt <= clock.GetUtcNow())
        {
            throw new ArgumentException("The verifier challenge expired while signing.", nameof(challenge));
        }

        return signed;
    }

    /// <summary>
    /// Authenticates a request against a verifier DID and exact audience pinned independently
    /// by the holder. A DID read from the request itself must NEVER become trusted by default.
    /// Only after success may the holder inspect the requested issuer and approve disclosure.
    /// </summary>
    public static bool TryRead(string requestJwt, string expectedVerifierDid, string expectedAudience,
        TimeProvider clock, out PresentationChallenge? challenge)
    {
        ArgumentNullException.ThrowIfNull(clock);
        challenge = null;

        if (string.IsNullOrWhiteSpace(requestJwt) ||
            string.IsNullOrWhiteSpace(expectedAudience) ||
            expectedAudience.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedVerifierDid, out var verifierPublicKey) ||
            !StrictJwtReader.TryRead(requestJwt, "herossid-request+jwt", MaximumRequestLength, out var payload) ||
            payload.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(payload, "iss", out var issuer) ||
            !string.Equals(issuer, expectedVerifierDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) ||
            !string.Equals(audience, expectedAudience, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) ||
            !PresentationChallengePolicy.IsValidNonce(nonce) ||
            !StrictJwtReader.TryGetString(payload, "trustedIssuerDid", out var trustedIssuerDid) ||
            trustedIssuerDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out _) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "exp", out var expiresAt))
        {
            return false;
        }

        decimal now = PresentationChallengePolicy.NumericDate(clock.GetUtcNow());
        if (issuedAt > now || expiresAt <= now || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 300 ||
            expiresAt - now > (decimal)InMemoryPresentationChallengeStore.MaximumLifetime.TotalSeconds ||
            !Ed25519JwtSigner.VerifySignedJwt(requestJwt, verifierPublicKey))
        {
            return false;
        }

        // JWT NumericDate permits fractions; reconstruct the exact verifier request expiry
        // instead of rounding seconds down and silently shortening a fresh challenge.
        challenge = new PresentationChallenge
        {
            Nonce = nonce,
            Audience = audience,
            TrustedIssuerDid = trustedIssuerDid,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddTicks((long)(expiresAt * TimeSpan.TicksPerSecond))
        };
        return true;
    }

    /// <summary>
    /// Creates the existing full-disclosure holder response ONLY after verifying the request
    /// signature and independently pinned verifier identity and audience. The wallet must
    /// still display all disclosed claims and obtain informed consent before invoking it.
    /// </summary>
    public static string CreatePresentation(string requestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string holderDid, byte[] holderPrivateKey, TimeProvider clock)
    {
        if (!TryRead(requestJwt, trustedVerifierDid, expectedAudience, clock, out var challenge) || challenge is null)
        {
            throw new ArgumentException("The verifier request is not authenticated, bound or live.", nameof(requestJwt));
        }

        return OfflinePresentationCreator.Create(challenge, credentialJwt, holderDid, holderPrivateKey, clock);
    }
}
