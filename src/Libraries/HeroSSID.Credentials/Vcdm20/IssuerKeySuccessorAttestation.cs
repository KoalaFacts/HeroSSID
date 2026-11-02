using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Bounded, two-party Ed25519 evidence that a pinned issuer key and a proposed
/// successor key both signed the same verifier-targeted transition statement.
/// This does not rotate an immutable did:key, enroll the successor, transfer
/// trust automatically, check issuer status or recover a lost previous key.
/// </summary>
public static class IssuerKeySuccessorAttestation
{
    /// <summary>Non-secret purpose boundary for stored verifier challenges.</summary>
    public const string ChallengePurposePrefix = "issuer-successor:";
    private const string HeaderType = "herossid-issuer-successor+jwt";
    private const int MaximumJwtLength = 4_096;
    private const int MaximumEnvelopeLength = 16_384;
    private const int LifetimeSeconds = 300;

    /// <summary>
    /// Create a verifier-specific two-signature continuity statement. Both
    /// independently held 32-byte Ed25519 seeds must match their distinct did:key
    /// identifiers. The caller supplies a random, verifier-issued nonce, owns
    /// both seed buffers and must clear them after use. No key is persisted.
    /// </summary>
    public static string Create(
        string previousIssuerDid, string successorIssuerDid,
        byte[] previousIssuerSeed, byte[] successorIssuerSeed,
        Uri verifierAudience, string challengeNonce, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(previousIssuerDid);
        ArgumentNullException.ThrowIfNull(successorIssuerDid);
        ArgumentNullException.ThrowIfNull(previousIssuerSeed);
        ArgumentNullException.ThrowIfNull(successorIssuerSeed);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(challengeNonce);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(previousIssuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(successorIssuerDid, out _) ||
            string.Equals(previousIssuerDid, successorIssuerDid, StringComparison.Ordinal) ||
            previousIssuerSeed.Length != 32 || previousIssuerSeed.All(static b => b == 0) ||
            successorIssuerSeed.Length != 32 || successorIssuerSeed.All(static b => b == 0) ||
            !ValidAudience(verifierAudience) || !ValidNonce(challengeNonce))
        {
            throw new ArgumentException("Distinct did:key issuer controls, HTTPS verifier audience and strong challenge nonce are required.");
        }

        long issued = clock.GetUtcNow().ToUnixTimeSeconds();
        if (issued < 0 || issued > 253402300499)
        {
            throw new ArgumentException("Issuer successor attestation clock is outside the supported UTC range.", nameof(clock));
        }

        string statement = JsonSerializer.Serialize(new
        {
            version = 1,
            previousIssuer = previousIssuerDid,
            successorIssuer = successorIssuerDid,
            aud = verifierAudience.AbsoluteUri,
            nonce = challengeNonce,
            iat = issued,
            exp = issued + LifetimeSeconds
        });
        string previousSignature = Ed25519JwtSigner.CreateSignedJwt(
            Header(previousIssuerDid), statement, previousIssuerSeed);
        string successorSignature = Ed25519JwtSigner.CreateSignedJwt(
            Header(successorIssuerDid), statement, successorIssuerSeed);
        string envelope = JsonSerializer.Serialize(new { previousSignature, successorSignature });

        if (envelope.Length > MaximumEnvelopeLength ||
            !TryVerify(envelope, previousIssuerDid, verifierAudience, challengeNonce,
                clock.GetUtcNow(), out var verifiedSuccessor) ||
            !string.Equals(verifiedSuccessor, successorIssuerDid, StringComparison.Ordinal))
        {
            throw new ArgumentException("Both private seeds must sign the same valid successor statement.");
        }

        return envelope;
    }

    /// <summary>
    /// Validate both Ed25519 signatures against a previously pinned issuer DID,
    /// the same exact statement, an independently pinned HTTPS verifier and nonce,
    /// and a strictly bounded five-minute UTC interval. The successor DID is
    /// disclosed only after verification. This is NOT authorization or an
    /// automatic trust-list update; callers must reject replay and apply local
    /// enrollment, compromise and identity policies separately.
    /// </summary>
    public static bool TryVerify(
        string attestationJson, string trustedPreviousIssuerDid,
        Uri expectedVerifierAudience, string expectedNonce,
        DateTimeOffset now, out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(attestationJson);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedVerifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);

        successorIssuerDid = string.Empty;
        if (attestationJson.Length is 0 or > MaximumEnvelopeLength ||
            !ValidAudience(expectedVerifierAudience) || !ValidNonce(expectedNonce) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                trustedPreviousIssuerDid, out var previousPublicKey))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(attestationJson,
                new JsonDocumentOptions { MaxDepth = 6 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Count() != 2 ||
                !StrictJwtReader.TryGetString(root, "previousSignature", out var previousJwt) ||
                !StrictJwtReader.TryGetString(root, "successorSignature", out var successorJwt) ||
                !StrictJwtReader.TryRead(previousJwt, HeaderType, MaximumJwtLength,
                    out var previousStatement, KeyId(trustedPreviousIssuerDid)) ||
                !Ed25519JwtSigner.VerifySignedJwt(previousJwt, previousPublicKey) ||
                previousStatement.EnumerateObject().Count() != 7 ||
                !previousStatement.TryGetProperty("version", out var version) ||
                version.ValueKind != JsonValueKind.Number ||
                !version.TryGetInt32(out var versionNumber) || versionNumber != 1 ||
                !StrictJwtReader.TryGetString(previousStatement, "previousIssuer", out var previousDid) ||
                !string.Equals(previousDid, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(previousStatement, "successorIssuer", out var candidate) ||
                string.Equals(candidate, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
                candidate.Length > 128 ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(candidate, out var successorPublicKey) ||
                !StrictJwtReader.TryGetString(previousStatement, "aud", out var audience) ||
                !string.Equals(audience, expectedVerifierAudience.AbsoluteUri, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(previousStatement, "nonce", out var nonce) ||
                !string.Equals(nonce, expectedNonce, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetTimestamp(previousStatement, "iat", out long issued) ||
                !StrictJwtReader.TryGetTimestamp(previousStatement, "exp", out long expires) ||
                issued > now.ToUnixTimeSeconds() || expires <= now.ToUnixTimeSeconds() ||
                expires <= issued || expires - issued > LifetimeSeconds ||
                !StrictJwtReader.TryRead(successorJwt, HeaderType, MaximumJwtLength,
                    out var successorStatement, KeyId(candidate)) ||
                !string.Equals(previousStatement.GetRawText(), successorStatement.GetRawText(),
                    StringComparison.Ordinal) ||
                !Ed25519JwtSigner.VerifySignedJwt(successorJwt, successorPublicKey))
            {
                return false;
            }

            successorIssuerDid = candidate;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Issue a tenant-owned issuer-key-successor challenge in a storage purpose
    /// namespace distinct from ordinary credential presentation challenges.
    /// The returned challenge exposes only the public HTTPS audience.
    /// The caller must independently authenticate the trusted previous issuer.
    /// </summary>
    public static PresentationChallenge IssueChallenge(
        Guid verifierTenantId, Uri verifierAudience,
        string trustedPreviousIssuerDid, IPresentationChallengeStore challenges,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(challenges);
        if (!ValidAudience(verifierAudience) ||
            verifierAudience.AbsoluteUri.Length > 2_000 ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(
                trustedPreviousIssuerDid, out _))
        {
            throw new ArgumentException(
                "Canonical HTTPS verifier audience and pinned Ed25519 previous issuer are required.");
        }

        var challenge = challenges.Issue(verifierTenantId,
            StoreAudience(verifierAudience), trustedPreviousIssuerDid, lifetime);
        return challenge with { Audience = verifierAudience.AbsoluteUri };
    }

    /// <summary>
    /// Validate authentic two-key Ed25519 control evidence and atomically
    /// consume exactly one verifier-owned issuer-successor challenge.
    /// Success does NOT enroll any issuer, validate identity or grant authority.
    /// Multi-replica verifiers must use one shared durable atomic challenge store.
    /// </summary>
    public static bool TryVerifyAndConsume(
        string attestationJson, string trustedPreviousIssuerDid,
        Uri expectedVerifierAudience, string expectedNonce,
        Guid verifierTenantId, IPresentationChallengeStore challenges,
        TimeProvider clock, out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(attestationJson);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedVerifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        successorIssuerDid = string.Empty;

        if (!ValidAudience(expectedVerifierAudience) ||
            expectedVerifierAudience.AbsoluteUri.Length > 2_000)
        {
            return false;
        }

        string audienceInStore = StoreAudience(expectedVerifierAudience);
        var retained = challenges.Find(verifierTenantId, audienceInStore, expectedNonce);
        if (retained is null ||
            !string.Equals(retained.TrustedIssuerDid, trustedPreviousIssuerDid,
                StringComparison.Ordinal) ||
            !TryVerify(attestationJson, trustedPreviousIssuerDid,
                expectedVerifierAudience, expectedNonce, clock.GetUtcNow(), out _))
        {
            return false;
        }

        // The store atomically rechecks tenant, purpose, nonce and expiry.
        // A competing acceptor or expired challenge fails closed.
        if (!challenges.TryConsume(verifierTenantId, audienceInStore, expectedNonce))
        {
            return false;
        }

        // Verify again after a potentially blocked remote consume. A proof or
        // challenge expiring during that wait cannot release the successor.
        var completedAt = clock.GetUtcNow();
        if (retained.ExpiresAt <= completedAt ||
            !TryVerify(attestationJson, trustedPreviousIssuerDid,
                expectedVerifierAudience, expectedNonce, completedAt,
                out string authenticatedSuccessor))
        {
            return false;
        }

        successorIssuerDid = authenticatedSuccessor;
        return true;
    }

    /// <summary>
    /// Opt-in successor admission requiring a verifier-owned, separately enrolled
    /// successor DID. A valid two-key claim alone MUST NOT select its own pin.
    /// This test-first stub intentionally rejects all requests until implemented.
    /// </summary>
    public static bool TryVerifyAndConsumePinnedSuccessor(
        string attestationJson, string trustedPreviousIssuerDid,
        string expectedSuccessorIssuerDid, Uri expectedVerifierAudience,
        string expectedNonce, Guid verifierTenantId,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(attestationJson);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedSuccessorIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedVerifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        successorIssuerDid = string.Empty;
        return false;
    }

    private static string StoreAudience(Uri verifierAudience) =>
        ChallengePurposePrefix + verifierAudience.AbsoluteUri;

    private static string Header(string did) =>
        JsonSerializer.Serialize(new { alg = "EdDSA", typ = HeaderType, kid = KeyId(did) });

    private static string KeyId(string did) => did + "#" + did["did:key:".Length..];

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        !string.IsNullOrEmpty(uri.Host) && string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Fragment) && uri.AbsoluteUri.Length <= 2_048;

    private static bool ValidNonce(string value) =>
        value.Length is >= 20 and <= 128 &&
        value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
