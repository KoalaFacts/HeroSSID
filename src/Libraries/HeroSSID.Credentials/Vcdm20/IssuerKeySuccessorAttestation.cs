using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Bounded, two-party Ed25519 evidence that a pinned issuer key and a proposed
/// successor key both signed the same verifier-targeted transition statement.
/// This does not rotate an immutable did:key, enroll the successor, transfer
/// trust automatically, check issuer status or recover a lost previous key.
/// </summary>
public static class IssuerKeySuccessorAttestation
{
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
