using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// A purpose-separated, verifier Ed25519-signed one-use issuer-key successor request.
/// The old and new key controllers must independently pin the verifier DID,
/// audience and previous issuer DID before signing their continuity statement.
/// This private HeroSSID format is not an OpenID4VP Request Object, issuer
/// enrollment, compromise detection, identity proof or business authority.
/// </summary>
public static class IssuerSuccessorVerifierRequest
{
    private const string HeaderType = "herossid-issuer-successor-request+jwt";
    private const string Purpose = "issuer-key-successor";
    private const int MaximumRequestLength = 8_192;

    /// <summary>
    /// Sign a verifier-owned, already-retained successor challenge using the
    /// verifier's independent Ed25519 seed. Caller protects and clears the seed.
    /// A signature cannot make an untrusted verifier legitimate.
    /// </summary>
    public static string Create(
        PresentationChallenge challenge, string verifierDid,
        byte[] verifierSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(verifierDid);
        ArgumentNullException.ThrowIfNull(verifierSeed);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        if (!ValidAudience(challenge.Audience) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                challenge.TrustedIssuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(verifierDid, out var publicKey) ||
            !PresentationChallengePolicy.IsValidNonce(challenge.Nonce) ||
            verifierSeed.Length != 32 || verifierSeed.All(static value => value == 0) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("A live, purpose-bound challenge and authentic verifier Ed25519 did:key are required.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = HeaderType,
            kid = KeyId(verifierDid)
        });
        string payload = JsonSerializer.Serialize(new
        {
            iss = verifierDid,
            aud = challenge.Audience,
            previousIssuerDid = challenge.TrustedIssuerDid,
            nonce = challenge.Nonce,
            purpose = Purpose,
            iat = PresentationChallengePolicy.NumericDate(now),
            exp = PresentationChallengePolicy.NumericDate(challenge.ExpiresAt)
        });

        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, verifierSeed);
        if (signed.Length > MaximumRequestLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, publicKey) ||
            !TryRead(signed, verifierDid, challenge.Audience,
                challenge.TrustedIssuerDid, clock, out _))
        {
            throw new ArgumentException("The verifier signing seed does not match its DID or the challenge is no longer live.",
                nameof(verifierSeed));
        }

        return signed;
    }

    /// <summary>
    /// Independently authenticate an issuer-successor request. All three
    /// expected identities/locations MUST come from the old/new key controllers'
    /// separately trusted policy, never from unverified request claims.
    /// Verification alone does not authorize key rollover or new credentials.
    /// </summary>
    public static bool TryRead(
        string requestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedPreviousIssuerDid, TimeProvider clock,
        out PresentationChallenge? challenge)
    {
        ArgumentNullException.ThrowIfNull(requestJwt);
        ArgumentNullException.ThrowIfNull(expectedVerifierDid);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(clock);
        challenge = null;

        if (!ValidAudience(expectedAudience) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                expectedVerifierDid, out var verifierPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                expectedPreviousIssuerDid, out _) ||
            !StrictJwtReader.TryRead(requestJwt, HeaderType, MaximumRequestLength,
                out var payload, KeyId(expectedVerifierDid)) ||
            payload.EnumerateObject().Count() != 7 ||
            !StrictJwtReader.TryGetString(payload, "iss", out var signer) ||
            !string.Equals(signer, expectedVerifierDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) ||
            !string.Equals(audience, expectedAudience, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "previousIssuerDid", out var previousDid) ||
            !string.Equals(previousDid, expectedPreviousIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) ||
            !PresentationChallengePolicy.IsValidNonce(nonce) ||
            !StrictJwtReader.TryGetString(payload, "purpose", out var purpose) ||
            !string.Equals(purpose, Purpose, StringComparison.Ordinal) ||
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

        challenge = new PresentationChallenge
        {
            Audience = audience,
            TrustedIssuerDid = previousDid,
            Nonce = nonce,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddTicks(
                (long)(expiresAt * TimeSpan.TicksPerSecond))
        };
        return true;
    }

    private static string KeyId(string did) => did + "#" + did["did:key:".Length..];

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2_000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);
}
