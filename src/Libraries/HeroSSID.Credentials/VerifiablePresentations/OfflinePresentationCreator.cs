using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Holder-side creation of the full-disclosure HeroSSID vp+jwt profile using a holder-owned
/// Ed25519 private key. No issuer database, holder enrollment service or key escrow is needed.
/// This is not OpenID4VP, selective disclosure or verifier authorization.
/// </summary>
public static class OfflinePresentationCreator
{
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumPresentationLength = 131_072;
    private const string PresentationHeader = "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}";

    /// <summary>
    /// Creates a holder-signed response bound to a verifier-issued challenge, preserving the
    /// exact original issuer-signed credential. The holder must independently approve the
    /// destination and all claims before calling. The caller owns and must eventually clear
    /// the private-key buffer; this method does not retain or erase it.
    /// </summary>
    /// <remarks>
    /// A self-certifying issuer signature is checked, but issuer trust, live revocation,
    /// verifier authenticity, holder consent and business authorization are external policy.
    /// The verifier must use its own stored challenge rather than trusting this input.
    /// </remarks>
    public static string Create(
        PresentationChallenge challenge, string credentialJwt, string holderDid,
        byte[] holderPrivateKey, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(holderPrivateKey);
        ArgumentNullException.ThrowIfNull(clock);

        var now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(challenge.Audience) ||
            challenge.Audience.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            string.IsNullOrWhiteSpace(challenge.TrustedIssuerDid) ||
            challenge.TrustedIssuerDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !PresentationChallengePolicy.IsValidNonce(challenge.Nonce) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("A live, bounded verifier challenge is required.", nameof(challenge));
        }

        if (holderDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey))
        {
            throw new ArgumentException("The holder must be a valid self-certifying Ed25519 did:key.", nameof(holderDid));
        }

        if (holderPrivateKey.Length != 32 || holderPrivateKey.All(static value => value == 0))
        {
            throw new ArgumentException("A nonzero 32-byte holder Ed25519 seed is required.", nameof(holderPrivateKey));
        }

        long nowSeconds = now.ToUnixTimeSeconds();
        if (!StrictJwtReader.TryRead(credentialJwt, "vc+jwt", MaximumCredentialLength, out var credential) ||
            !StrictJwtReader.TryGetString(credential, "iss", out var issuerDid) ||
            !string.Equals(issuerDid, challenge.TrustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(credential, "sub", out var signedHolder) ||
            !string.Equals(signedHolder, holderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetTimestamp(credential, "iat", out long issuedAt) ||
            issuedAt > nowSeconds ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out var issuerPublicKey) ||
            !Ed25519JwtSigner.VerifySignedJwt(credentialJwt, issuerPublicKey) ||
            !HasValidCredentialSubject(credential, signedHolder))
        {
            throw new ArgumentException("A valid issuer-signed credential bound to this holder and issuer is required.", nameof(credentialJwt));
        }

        if (credential.TryGetProperty("nbf", out _) &&
            (!StrictJwtReader.TryGetTimestamp(credential, "nbf", out long notBefore) ||
             notBefore > nowSeconds))
        {
            throw new ArgumentException("The credential is not yet valid.", nameof(credentialJwt));
        }

        decimal expiry = PresentationChallengePolicy.NumericDate(challenge.ExpiresAt);
        if (credential.TryGetProperty("exp", out var originalExpiry) &&
            originalExpiry.ValueKind != JsonValueKind.Null)
        {
            if (!StrictJwtReader.TryGetTimestamp(credential, "exp", out long expiresAt) ||
                expiresAt <= issuedAt)
            {
                throw new ArgumentException("The credential expiry is invalid.", nameof(credentialJwt));
            }

            expiry = Math.Min(expiry, expiresAt);
        }

        var issued = PresentationChallengePolicy.NumericDate(now);
        if (expiry <= issued)
        {
            throw new ArgumentException("The challenge or original credential has expired.", nameof(challenge));
        }

        // Preserve the issuer's exact compact JWT. Only the holder signs the outer envelope.
        // NumericDates are fractional: short-lived verifier requests must not lose a second.
        string payload = JsonSerializer.Serialize(new
        {
            iss = holderDid,
            aud = challenge.Audience,
            nonce = challenge.Nonce,
            iat = issued,
            exp = expiry,
            vp = new { verifiableCredential = new[] { credentialJwt } }
        });
        string presentation = Ed25519JwtSigner.CreateSignedJwt(PresentationHeader, payload, holderPrivateKey);
        if (presentation.Length > MaximumPresentationLength)
        {
            throw new ArgumentException("The full-disclosure presentation exceeds the profile limit.", nameof(credentialJwt));
        }

        // The provided seed must actually control the DID used in the signed proof.
        if (!Ed25519JwtSigner.VerifySignedJwt(presentation, holderPublicKey))
        {
            throw new ArgumentException("The holder private key does not match the holder DID.", nameof(holderPrivateKey));
        }

        if (PresentationChallengePolicy.NumericDate(clock.GetUtcNow()) >= expiry)
        {
            throw new ArgumentException("The challenge or credential expired while signing.", nameof(challenge));
        }

        return presentation;
    }

    private static bool HasValidCredentialSubject(JsonElement credential, string signedHolder)
    {
        if (!credential.TryGetProperty("vc", out var vc) ||
            vc.ValueKind != JsonValueKind.Object ||
            !vc.TryGetProperty("type", out var types) ||
            types.ValueKind != JsonValueKind.Array ||
            !vc.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        bool containsBaseType = false;
        foreach (var item in types.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString()))
            {
                return false;
            }

            containsBaseType |= string.Equals(item.GetString(), "VerifiableCredential", StringComparison.Ordinal);
        }

        if (!containsBaseType)
        {
            return false;
        }

        return !subject.TryGetProperty("id", out _) ||
               (StrictJwtReader.TryGetString(subject, "id", out var id) &&
                string.Equals(id, signedHolder, StringComparison.Ordinal));
    }
}
