using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Result of checking an issuer-signed VC 1.1 and a real holder-signed VP against a one-use challenge.</summary>
public enum JwtVcJsonPresentationCheckResult
{
    /// <summary>Malformed, forged, expired, misbound, untrusted or previously consumed proof.</summary>
    Invalid,

    /// <summary>
    /// Original issuer and holder signatures and the one-use challenge passed.
    /// Revocation, identity vetting, human consent and business authority were NOT established.
    /// </summary>
    SignedButStatusUnchecked
}

/// <summary>
/// Opt-in W3C VC Data Model 1.1 JWT VP containing one unchanged issuer-signed
/// jwt_vc_json credential. The signed VP follows the OpenID4VP 1.0 Appendix
/// B.1.3.1.5 nested JWT shape, but the verifier's signed request is a private
/// HeroSSID profile, NOT OpenID4VP or an independently tested wallet exchange.
/// </summary>
public static class JwtVcJsonPresentation
{
    private const string BaseContext = "https://www.w3.org/2018/credentials/v1";
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumPresentationLength = 131_072;
    private static readonly string[] PresentationContexts = [BaseContext];
    private static readonly string[] PresentationTypes = ["VerifiablePresentation"];

    /// <summary>
    /// Verify the pinned verifier's signed request and the issuer's original
    /// credential before signing with the holder's own Ed25519 seed.
    /// The calling wallet MUST show all disclosed claims and obtain informed
    /// consent before invoking this full-disclosure method.
    /// </summary>
    public static string Create(string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedSubjectContextUri,
        string holderDid, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineSignedPresentationRequest.TryRead(
                signedRequestJwt, trustedVerifierDid, expectedAudience, clock, out var challenge) ||
            challenge is null)
        {
            throw new ArgumentException("A live signed request from an independently pinned verifier is required.",
                nameof(signedRequestJwt));
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumCredentialLength ||
            holderSeed.Length != 32 || holderSeed.All(static value => value == 0) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey) ||
            !JwtVcJsonCredential.TryVerify(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri, now, out _) ||
            !TryReadCredentialExpiry(credentialJwt, out long credentialExpires))
        {
            throw new ArgumentException("An authentic issuer credential and an actual holder signing key are required.",
                nameof(credentialJwt));
        }

        decimal issuedAt = PresentationChallengePolicy.NumericDate(now);
        decimal expiresAt = Math.Min(
            Math.Min(PresentationChallengePolicy.NumericDate(challenge.ExpiresAt), credentialExpires),
            PresentationChallengePolicy.NumericDate(now.Add(InMemoryPresentationChallengeStore.MaximumLifetime)));
        if (expiresAt <= issuedAt)
        {
            throw new ArgumentException("The verifier request or original credential has expired.", nameof(credentialJwt));
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "vp+jwt",
            kid = KeyId(holderDid)
        });
        // This is the JWT-secured VC1.1 VP shape from OpenID4VP Appendix B,
        // not a direct VCDM 2.0 EnvelopedVerifiableCredential.
        string payload = JsonSerializer.Serialize(new
        {
            iss = holderDid,
            aud = challenge.Audience,
            nonce = challenge.Nonce,
            iat = issuedAt,
            nbf = issuedAt,
            exp = expiresAt,
            vp = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["@context"] = PresentationContexts,
                ["type"] = PresentationTypes,
                ["verifiableCredential"] = new[] { credentialJwt }
            }
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, holderSeed);
        if (signed.Length > MaximumPresentationLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, holderPublicKey))
        {
            throw new ArgumentException("Holder signing seed does not control the claimed did:key or VP is oversized.",
                nameof(holderSeed));
        }

        if (PresentationChallengePolicy.NumericDate(clock.GetUtcNow()) >= expiresAt)
        {
            throw new ArgumentException("The holder presentation expired while signing.", nameof(credentialJwt));
        }

        return signed;
    }

    /// <summary>
    /// Check an authentic holder signature, the unchanged issuer signature,
    /// strict nested VC1.1 context/type/subject policy and an atomic verifier
    /// challenge. Return signed subject claims ONLY after successful consumption.
    /// Shared, atomic challenge storage is required for multi-instance verifiers.
    /// No revocation or business authorization is checked.
    /// </summary>
    public static JwtVcJsonPresentationCheckResult Check(string presentationJwt,
        Guid verifierTenantId, string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedAudience, expectedNonce) ||
            !StrictJwtReader.IsCanonicalCompact(presentationJwt, MaximumPresentationLength) ||
            !TryReadUntrustedHolder(presentationJwt, out string holderDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // The only accepted issuer and audience come from the verifier's own
        // challenge store. Neither the untrusted VP nor its embedded VC grants trust.
        var challenge = challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        DateTimeOffset now = clock.GetUtcNow();
        if (challenge is null || challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) ||
            !StrictJwtReader.TryRead(presentationJwt, "vp+jwt", MaximumPresentationLength,
                out var payload, KeyId(holderDid)) ||
            payload.EnumerateObject().Count() != 7 ||
            !StrictJwtReader.TryGetString(payload, "iss", out string signedHolder) ||
            !string.Equals(signedHolder, holderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out string audience) ||
            !string.Equals(audience, expectedAudience, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "nonce", out string nonce) ||
            !string.Equals(nonce, expectedNonce, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "iat", out decimal issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "nbf", out decimal notBefore) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "exp", out decimal expiresAt) ||
            !TryReadEmbeddedCredential(payload, out string credentialJwt) ||
            !Ed25519JwtSigner.VerifySignedJwt(presentationJwt, holderPublicKey))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        decimal current = PresentationChallengePolicy.NumericDate(now);
        if (notBefore != issuedAt || issuedAt > current || expiresAt <= current ||
            expiresAt <= issuedAt || expiresAt - issuedAt > 300 ||
            expiresAt > PresentationChallengePolicy.NumericDate(challenge.ExpiresAt) ||
            !JwtVcJsonCredential.TryVerify(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri, now, out var subject) ||
            !TryReadCredentialExpiry(credentialJwt, out long credentialExpires) ||
            expiresAt > credentialExpires)
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // Atomic consume is the authorization boundary for one-time presentation
        // verification; an older duplicate must never return verified claims.
        if (!challenges.TryConsume(verifierTenantId, expectedAudience, expectedNonce))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // Shared backing stores may block on locks. After consumption, recheck
        // wall-clock expiry and the issuer's signed validity. Spent stays spent.
        now = clock.GetUtcNow();
        if (challenge.ExpiresAt <= now ||
            expiresAt <= PresentationChallengePolicy.NumericDate(now) ||
            !JwtVcJsonCredential.TryVerify(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri, now, out _))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        verifiedSubject = subject;
        return JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked;
    }

    private static bool TryReadEmbeddedCredential(JsonElement payload, out string credentialJwt)
    {
        credentialJwt = string.Empty;
        if (!payload.TryGetProperty("vp", out var vp) ||
            vp.ValueKind != JsonValueKind.Object ||
            vp.EnumerateObject().Count() != 3 ||
            !HasSingleValue(vp, "@context", BaseContext) ||
            !HasSingleValue(vp, "type", "VerifiablePresentation") ||
            !vp.TryGetProperty("verifiableCredential", out var credentials) ||
            credentials.ValueKind != JsonValueKind.Array || credentials.GetArrayLength() != 1 ||
            credentials[0].ValueKind != JsonValueKind.String)
        {
            return false;
        }

        credentialJwt = credentials[0].GetString() ?? string.Empty;
        return StrictJwtReader.IsCanonicalCompact(credentialJwt, MaximumCredentialLength);
    }

    private static bool HasSingleValue(JsonElement value, string name, string expected)
    {
        return value.TryGetProperty(name, out var items) &&
            items.ValueKind == JsonValueKind.Array && items.GetArrayLength() == 1 &&
            items[0].ValueKind == JsonValueKind.String &&
            string.Equals(items[0].GetString(), expected, StringComparison.Ordinal);
    }

    private static bool TryReadUntrustedHolder(string jwt, out string holderDid)
    {
        holderDid = string.Empty;
        try
        {
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            return StrictJwtReader.TryGetString(document.RootElement, "iss", out holderDid) &&
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

    private static bool TryReadCredentialExpiry(string credentialJwt, out long expiresAt)
    {
        expiresAt = 0;
        if (!StrictJwtReader.IsCanonicalCompact(credentialJwt, MaximumCredentialLength))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(credentialJwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            return StrictJwtReader.TryGetTimestamp(document.RootElement, "exp", out expiresAt);
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

    private static string KeyId(string holderDid) => holderDid + "#" + holderDid["did:key:".Length..];
}
