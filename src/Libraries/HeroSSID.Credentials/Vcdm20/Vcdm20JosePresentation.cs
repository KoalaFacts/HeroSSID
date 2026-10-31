using System.Globalization;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>Result of verifying a signed VC2 holder presentation against a consumed challenge.</summary>
public enum Vcdm20PresentationCheckResult
{
    /// <summary>Malformed, forged, expired, untrusted or previously consumed proof.</summary>
    Invalid,

    /// <summary>
    /// The issuer statement, holder control and one-use request were checked.
    /// Revocation, issuer registration, real-world identity and authorization were NOT checked.
    /// </summary>
    SignedButStatusUnchecked
}

/// <summary>
/// Opt-in Ed25519 direct JOSE VP 2.0 containing an EnvelopedVerifiableCredential.
/// Full disclosure of exactly one issuer-signed VC2 JWT; not an OpenID4VP
/// exchange, live status check, JSON-LD processor, wallet or conformance certification.
/// </summary>
public static class Vcdm20JosePresentation
{
    private const string BaseContext = "https://www.w3.org/ns/credentials/v2";
    private const string DataPrefix = "data:application/vc+jwt,";
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumPresentationLength = 131_072;
    private static readonly string[] BaseContexts = [BaseContext];
    private static readonly string[] PresentationTypes = ["VerifiablePresentation"];
    private static readonly string[] EnvelopedTypes = ["EnvelopedVerifiableCredential"];
    private static readonly string[] DateFormats =
    [
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"
    ];

    /// <summary>
    /// Holder creates an actual Ed25519-signed VC2 envelope after verifying a signed
    /// request against the independently pinned verifier DID and exact audience.
    /// The calling holder UI MUST first display all claims and obtain consent.
    /// The caller owns, protects and clears the private seed; it is never persisted here.
    /// </summary>
    public static string Create(
        string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedContextUri,
        string holderDid, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if ((!OfflineSignedPresentationRequest.TryRead(
                signedRequestJwt, trustedVerifierDid, expectedAudience, clock, out var challenge) &&
            !OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, trustedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, clock, out challenge)) ||
            challenge is null)
        {
            throw new ArgumentException("An authentic request from the pinned verifier is required.", nameof(signedRequestJwt));
        }

        var now = clock.GetUtcNow();
        if (holderSeed.Length != 32 || holderSeed.All(static b => b == 0) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey) ||
            !Vcdm20JoseCredential.TryVerify(
                credentialJwt, challenge.TrustedIssuerDid, holderDid,
                expectedCredentialType, expectedContextUri, now, out _) ||
            !TryReadCredentialExpiry(credentialJwt, out var credentialUntil))
        {
            throw new ArgumentException("A real holder key and valid issuer-signed VC2 credential are required.", nameof(credentialJwt));
        }

        decimal issuedAt = PresentationChallengePolicy.NumericDate(now);
        decimal expiry = Math.Min(PresentationChallengePolicy.NumericDate(challenge.ExpiresAt),
            PresentationChallengePolicy.NumericDate(credentialUntil));
        if (expiry <= issuedAt)
        {
            throw new ArgumentException("The credential or verifier request has expired.", nameof(credentialJwt));
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "vp+jwt",
            kid = KeyId(holderDid)
        });
        string payload = JsonSerializer.Serialize(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = BaseContexts,
            ["type"] = PresentationTypes,
            ["holder"] = holderDid,
            ["verifiableCredential"] = new[]
            {
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["@context"] = BaseContexts,
                    ["type"] = EnvelopedTypes,
                    ["id"] = DataPrefix + credentialJwt
                }
            },
            ["aud"] = challenge.Audience,
            ["nonce"] = challenge.Nonce,
            ["iat"] = issuedAt,
            ["exp"] = expiry
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, holderSeed);
        if (signed.Length > MaximumPresentationLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, holderPublicKey))
        {
            throw new ArgumentException("The holder seed does not control the claimed DID or presentation is oversized.", nameof(holderSeed));
        }

        if (PresentationChallengePolicy.NumericDate(clock.GetUtcNow()) >= expiry)
        {
            throw new ArgumentException("The presentation expired while signing.", nameof(credentialJwt));
        }

        return signed;
    }

    /// <summary>
    /// Verifier checks real issuer and holder Ed25519 signatures, exact pinned context,
    /// credential type, issuer policy, audience/nonce and single-use atomic challenge
    /// consumption. Claims are returned ONLY on success. No revocation/status proof:
    /// SignedButStatusUnchecked MUST NOT be treated as authorization.
    /// Durable multi-replica verifiers must use a shared atomic challenge store.
    /// </summary>
    public static Vcdm20PresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;
        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedAudience, expectedNonce) ||
            !StrictJwtReader.IsCanonicalCompact(presentationJwt, MaximumPresentationLength) ||
            !TryReadUntrustedHolder(presentationJwt, out var holderDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        // A challenge always comes from the verifier's own store, never from holder claims.
        var challenge = challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        var now = clock.GetUtcNow();
        if (challenge is null || challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) ||
            !StrictJwtReader.TryRead(
                presentationJwt, "vp+jwt", MaximumPresentationLength,
                out var payload, KeyId(holderDid)) ||
            payload.EnumerateObject().Count() != 8 ||
            !HasOneString(payload, "@context", BaseContext) ||
            !HasOneString(payload, "type", "VerifiablePresentation") ||
            !StrictJwtReader.TryGetString(payload, "holder", out var signedHolder) ||
            !string.Equals(signedHolder, holderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) ||
            !string.Equals(audience, expectedAudience, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) ||
            !string.Equals(nonce, expectedNonce, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "exp", out var expiresAt) ||
            !TryReadEnvelopedCredential(payload, out var credentialJwt) ||
            !Ed25519JwtSigner.VerifySignedJwt(presentationJwt, holderPublicKey))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        decimal current = PresentationChallengePolicy.NumericDate(now);
        if (issuedAt > current || expiresAt <= current || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 300 ||
            expiresAt > PresentationChallengePolicy.NumericDate(challenge.ExpiresAt) ||
            !Vcdm20JoseCredential.TryVerify(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedContextUri, now, out var subject) ||
            !TryReadCredentialExpiry(credentialJwt, out var credentialUntil) ||
            expiresAt > PresentationChallengePolicy.NumericDate(credentialUntil))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        // Atomic consumption prevents concurrent verification/replay. A failure remains
        // a failure even when the caller supplied a correctly signed proof.
        if (!challenges.TryConsume(verifierTenantId, expectedAudience, expectedNonce))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        // A distributed store can block on a lock. Expiry must be rechecked AFTER
        // consumption; the nonce remains spent if it elapsed while waiting.
        now = clock.GetUtcNow();
        if (challenge.ExpiresAt <= now ||
            expiresAt <= PresentationChallengePolicy.NumericDate(now) ||
            !Vcdm20JoseCredential.TryVerify(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedContextUri, now, out _))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        verifiedSubject = subject;
        return Vcdm20PresentationCheckResult.SignedButStatusUnchecked;
    }

    private static bool TryReadUntrustedHolder(string jwt, out string holderDid)
    {
        holderDid = string.Empty;
        try
        {
            using var document = JsonDocument.Parse(
                Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            return StrictJwtReader.TryGetString(document.RootElement, "holder", out holderDid) &&
                holderDid.Length <= PresentationChallengePolicy.MaximumIdentifierLength;
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

    private static bool TryReadEnvelopedCredential(JsonElement payload, out string credentialJwt)
    {
        credentialJwt = string.Empty;
        if (!payload.TryGetProperty("verifiableCredential", out var list) ||
            list.ValueKind != JsonValueKind.Array || list.GetArrayLength() != 1 ||
            list[0].ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var envelope = list[0];
        if (envelope.EnumerateObject().Count() != 3 ||
            !HasOneString(envelope, "@context", BaseContext) ||
            !HasOneString(envelope, "type", "EnvelopedVerifiableCredential") ||
            !StrictJwtReader.TryGetString(envelope, "id", out var uri) ||
            !uri.StartsWith(DataPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        credentialJwt = uri[DataPrefix.Length..];
        return credentialJwt.Length <= MaximumCredentialLength &&
            StrictJwtReader.IsCanonicalCompact(credentialJwt, MaximumCredentialLength);
    }

    private static bool HasOneString(JsonElement obj, string property, string expected)
    {
        if (!obj.TryGetProperty(property, out var array) ||
            array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != 1)
        {
            return false;
        }

        return array[0].ValueKind == JsonValueKind.String &&
            string.Equals(array[0].GetString(), expected, StringComparison.Ordinal);
    }

    private static bool TryReadCredentialExpiry(string jwt, out DateTimeOffset validUntil)
    {
        validUntil = default;
        if (!StrictJwtReader.IsCanonicalCompact(jwt, MaximumCredentialLength))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            return StrictJwtReader.TryGetString(document.RootElement, "validUntil", out var timestamp) &&
                DateTimeOffset.TryParseExact(timestamp, DateFormats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out validUntil);
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

    private static string KeyId(string holderDid) =>
        holderDid + "#" + holderDid["did:key:".Length..];
}
