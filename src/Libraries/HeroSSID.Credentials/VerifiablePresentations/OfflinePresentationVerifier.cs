using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Outcome of an offline, full-disclosure holder presentation check.</summary>
public enum OfflinePresentationCheckResult
{
    /// <summary>Invalid signatures, challenge, binding, structure, expiry or prior consumption.</summary>
    Invalid,

    /// <summary>The original issuer-signed credential is in the authentic signed snapshot.</summary>
    Revoked,

    /// <summary>
    /// Real issuer and holder signatures, a fresh authentic status snapshot that does not list
    /// the credential, and atomic one-use challenge consumption have been checked.
    /// This does not establish business authorization or live issuer status.
    /// </summary>
    SignedNotListed
}

/// <summary>
/// Offline verifier for the local full-disclosure vp+jwt profile, with a verifier-owned
/// challenge store. No issuer database, remote DID lookup or holder private key is used.
/// Not an OpenID4VP endpoint, a third-party wallet interoperability test, or a trust registry.
/// </summary>
public static class OfflinePresentationVerifier
{
    private const int MaximumPresentationLength = 131_072;
    private const int MaximumCredentialLength = 65_536;

    /// <summary>
    /// Verifies holder control and original issuer provenance against a challenge previously
    /// issued by the verifier. Only the verifier may choose its trusted issuer when issuing
    /// that challenge. The caller must provision the challenge store and independently
    /// authorize the issuer; a process-local store is not a distributed replay defense.
    /// Store failure propagates rather than falling back to acceptance.
    /// </summary>
    public static OfflinePresentationCheckResult Check(
        string presentationJwt, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, IPresentationChallengeStore challenges,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);

        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedAudience, expectedNonce) ||
            string.IsNullOrWhiteSpace(presentationJwt) ||
            string.IsNullOrWhiteSpace(snapshotJwt) ||
            presentationJwt.Length > MaximumPresentationLength)
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        // Never take verifier policy or replay state from the holder's untrusted JWT.
        var challenge = challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        var now = clock.GetUtcNow();
        if (challenge is null ||
            !string.Equals(challenge.Nonce, expectedNonce, StringComparison.Ordinal) ||
            !string.Equals(challenge.Audience, expectedAudience, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(challenge.TrustedIssuerDid) ||
            challenge.TrustedIssuerDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        if (!StrictJwtReader.TryRead(presentationJwt, "vp+jwt", MaximumPresentationLength, out var envelope) ||
            envelope.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(envelope, "iss", out var holderDid) ||
            holderDid.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            !StrictJwtReader.TryGetString(envelope, "aud", out var audience) ||
            !string.Equals(audience, expectedAudience, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(envelope, "nonce", out var nonce) ||
            !string.Equals(nonce, expectedNonce, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.TryGetNumericDate(envelope, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(envelope, "exp", out var expiresAt) ||
            !envelope.TryGetProperty("vp", out var vp) || vp.ValueKind != JsonValueKind.Object ||
            vp.EnumerateObject().Count() != 1 ||
            !vp.TryGetProperty("verifiableCredential", out var credentials) ||
            credentials.ValueKind != JsonValueKind.Array || credentials.GetArrayLength() != 1 ||
            credentials[0].ValueKind != JsonValueKind.String)
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        decimal currentTime = PresentationChallengePolicy.NumericDate(now);
        if (issuedAt > currentTime || expiresAt <= currentTime || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 300 ||
            expiresAt > PresentationChallengePolicy.NumericDate(challenge.ExpiresAt) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderKey) ||
            !Ed25519JwtSigner.VerifySignedJwt(presentationJwt, holderKey))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        string credentialJwt = credentials[0].GetString()!;
        if (!StrictJwtReader.TryRead(credentialJwt, "vc+jwt", MaximumCredentialLength, out var credential) ||
            !StrictJwtReader.TryGetString(credential, "sub", out var signedHolder) ||
            !string.Equals(signedHolder, holderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(credential, "iss", out var issuer) ||
            !string.Equals(issuer, challenge.TrustedIssuerDid, StringComparison.Ordinal))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        // A presentation may not outlive the original credential even when both
        // separately remain unexpired at the instant of verification.
        if (credential.TryGetProperty("exp", out var credentialExpiry) &&
            credentialExpiry.ValueKind != JsonValueKind.Null &&
            (!StrictJwtReader.TryGetTimestamp(credential, "exp", out var expiry) || expiresAt > expiry))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        var status = OfflineCredentialVerifier.Check(credentialJwt, snapshotJwt, challenge.TrustedIssuerDid, now);
        if (status == OfflineCredentialCheckResult.Invalid)
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        if (status == OfflineCredentialCheckResult.Revoked)
        {
            return OfflinePresentationCheckResult.Revoked;
        }

        // Find is advisory. Only one verifier request can win the atomic consume,
        // including when another process races this signature verification.
        if (!challenges.TryConsume(verifierTenantId, expectedAudience, expectedNonce))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        // Durable consumption can wait on a database lock. Do not accept a credential,
        // presentation or signed status snapshot that expired while that lock was held.
        // The consumed challenge remains spent if the final freshness test fails.
        now = clock.GetUtcNow();
        if (challenge.ExpiresAt <= now ||
            expiresAt <= PresentationChallengePolicy.NumericDate(now) ||
            OfflineCredentialVerifier.Check(credentialJwt, snapshotJwt, challenge.TrustedIssuerDid, now) !=
                OfflineCredentialCheckResult.SignedNotListed)
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        return OfflinePresentationCheckResult.SignedNotListed;
    }
}
