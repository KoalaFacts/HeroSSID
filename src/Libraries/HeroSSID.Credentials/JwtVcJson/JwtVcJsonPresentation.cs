using System.Security.Cryptography;
using System.Text;
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
internal sealed record PinnedDidWebIssuerPresentationPolicy(
    string IssuerDid, string VerificationMethodId, byte[] PublicKey,
    string IssuerName, Uri CredentialId);

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

        return CreateForAuthenticatedChallenge(challenge, credentialJwt, expectedCredentialType,
            expectedSubjectContextUri, holderDid, holderSeed, clock);
    }

    /// <summary>
    /// Sign only after a caller within this assembly has authenticated the verifier
    /// and parsed its signed, nonce-bound request. Never trust holder-supplied
    /// issuer or audience values as a verifier policy.
    /// </summary>
    internal static string CreateForAuthenticatedChallenge(PresentationChallenge challenge,
        string credentialJwt, string expectedCredentialType, Uri expectedSubjectContextUri,
        string holderDid, byte[] holderSeed, TimeProvider clock, string? originalSignedRequestJwt = null,
        PinnedDidWebIssuerPresentationPolicy? pinnedDidWebIssuer = null)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumCredentialLength ||
            holderSeed.Length != 32 || holderSeed.All(static value => value == 0) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey) ||
            !TryVerifyIssuerCredential(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri,
                now, pinnedDidWebIssuer, out _) ||
            !TryReadCredentialExpiry(credentialJwt, out decimal credentialExpires))
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
        // The optional extension signs the EXACT compact verifier Request Object.
        // It does not replace independent relying-party storage of the original pin.
        if (originalSignedRequestJwt is not null &&
            !StrictJwtReader.IsCanonicalCompact(originalSignedRequestJwt, 16_384))
        {
            throw new ArgumentException("A canonical compact signed request is required.",
                nameof(originalSignedRequestJwt));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = holderDid,
            ["aud"] = challenge.Audience,
            ["nonce"] = challenge.Nonce,
            ["iat"] = issuedAt,
            ["nbf"] = issuedAt,
            ["exp"] = expiresAt,
            ["vp"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["@context"] = PresentationContexts,
                ["type"] = PresentationTypes,
                ["verifiableCredential"] = new[] { credentialJwt }
            }
        };
        if (originalSignedRequestJwt is not null)
        {
            claims["herossidRequestSha256"] = Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(originalSignedRequestJwt)));
        }

        string payload = JsonSerializer.Serialize(claims);
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
        out JsonElement verifiedSubject) =>
        CheckCore(presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
            expectedCredentialType, expectedSubjectContextUri, challenges, clock,
            null, out verifiedSubject);

    /// <summary>
    /// Reuse the original VC1.1 nested holder VP proof, but require the
    /// verifier's independently pinned did:web assertion key and original
    /// issuer name/credential ID. The verifier's challenge is consumed only
    /// after BOTH issuer and holder signatures authenticate.
    /// </summary>
    internal static JwtVcJsonPresentationCheckResult CheckWithPinnedDidWebIssuer(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType,
        Uri expectedSubjectContextUri, IPresentationChallengeStore challenges,
        TimeProvider clock, PinnedDidWebIssuerPresentationPolicy issuerPolicy,
        out JsonElement verifiedSubject) =>
        CheckCore(presentationJwt, verifierTenantId, expectedAudience,
            expectedNonce, expectedCredentialType, expectedSubjectContextUri,
            challenges, clock, null, out verifiedSubject,
            pinnedDidWebIssuer: issuerPolicy);

    /// <summary>
    /// Require the holder's actual Ed25519 signature over the exact original
    /// verifier request digest. The caller MUST authenticate the signed
    /// request and independently retain its SHA-256 before invoking this.
    /// </summary>
    internal static JwtVcJsonPresentationCheckResult CheckWithHolderSignedRequestHash(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        string requiredOriginalRequestSha256, out JsonElement verifiedSubject) =>
        CheckCore(presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
            expectedCredentialType, expectedSubjectContextUri, challenges, clock,
            requiredOriginalRequestSha256, out verifiedSubject);

    /// <summary>
    /// Wallet-only cryptographic preflight for an independently authenticated verifier
    /// Request Object. No verifier challenge is fetched or consumed, and no subject
    /// claims are disclosed by this API. This does not prove consent or live status.
    /// </summary>
    internal static bool IsAuthenticHolderBoundProofForWalletTransport(
        string presentationJwt, PresentationChallenge authenticatedRequestChallenge,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string requiredOriginalRequestSha256, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(authenticatedRequestChallenge);
        return CheckCore(presentationJwt, Guid.Empty,
            authenticatedRequestChallenge.Audience, authenticatedRequestChallenge.Nonce,
            expectedCredentialType, expectedSubjectContextUri,
            null, clock, requiredOriginalRequestSha256, out _,
            authenticatedRequestChallenge) ==
            JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked;
    }

    private static JwtVcJsonPresentationCheckResult CheckCore(string presentationJwt,
        Guid verifierTenantId, string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore? challenges, TimeProvider clock,
        string? requiredOriginalRequestSha256, out JsonElement verifiedSubject,
        PresentationChallenge? authenticatedWalletChallenge = null,
        PinnedDidWebIssuerPresentationPolicy? pinnedDidWebIssuer = null)
    {
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        if (authenticatedWalletChallenge is null)
        {
            ArgumentNullException.ThrowIfNull(challenges);
        }

        verifiedSubject = default;

        if ((authenticatedWalletChallenge is null &&
                !PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedAudience, expectedNonce)) ||
            !StrictJwtReader.IsCanonicalCompact(presentationJwt, MaximumPresentationLength) ||
            !TryReadUntrustedHolder(presentationJwt, out string holderDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderPublicKey))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // The only accepted issuer and audience come from the verifier's own
        // challenge store. Neither the untrusted VP nor its embedded VC grants trust.
        var challenge = authenticatedWalletChallenge ??
            challenges!.Find(verifierTenantId, expectedAudience, expectedNonce);
        DateTimeOffset now = clock.GetUtcNow();
        if (challenge is null ||
            (pinnedDidWebIssuer is not null &&
                !string.Equals(challenge.TrustedIssuerDid, pinnedDidWebIssuer.IssuerDid,
                    StringComparison.Ordinal)) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) ||
            !StrictJwtReader.TryRead(presentationJwt, "vp+jwt", MaximumPresentationLength,
                out var payload, KeyId(holderDid)) ||
            payload.EnumerateObject().Count() !=
                (requiredOriginalRequestSha256 is null ? 7 : 8) ||
            (requiredOriginalRequestSha256 is not null &&
                (!StrictJwtReader.TryGetString(payload, "herossidRequestSha256",
                    out var holderSignedRequestHash) ||
                 !string.Equals(holderSignedRequestHash,
                    requiredOriginalRequestSha256, StringComparison.Ordinal))) ||
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
            !TryVerifyIssuerCredential(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri,
                now, pinnedDidWebIssuer, out var subject) ||
            !TryReadCredentialExpiry(credentialJwt, out decimal credentialExpires) ||
            expiresAt > credentialExpires)
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // The Wallet preflight checks authentic proofs before any HTTP disclosure,
        // but it MUST NOT consume a verifier-owned challenge or expose subject data.
        // Actual acceptance remains a separate atomic verifier-only operation.
        if (authenticatedWalletChallenge is not null)
        {
            return JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked;
        }

        // Atomic consume is the authorization boundary for one-time presentation
        // verification; an older duplicate must never return verified claims.
        if (!challenges!.TryConsume(verifierTenantId, expectedAudience, expectedNonce))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        // Shared backing stores may block on locks. After consumption, recheck
        // wall-clock expiry and the issuer's signed validity. Spent stays spent.
        now = clock.GetUtcNow();
        if (challenge.ExpiresAt <= now ||
            expiresAt <= PresentationChallengePolicy.NumericDate(now) ||
            !TryVerifyIssuerCredential(credentialJwt, challenge.TrustedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri,
                now, pinnedDidWebIssuer, out _))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        verifiedSubject = subject;
        return JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked;
    }

    // The new did:web path never falls back to the legacy self-certifying
    // did:key verifier. A signature from an unpinned key must not be accepted
    // merely because the JWT supplies its own issuer or method identifiers.
    private static bool TryVerifyIssuerCredential(
        string credentialJwt, string trustedIssuerDid, string holderDid,
        string credentialType, Uri context, DateTimeOffset now,
        PinnedDidWebIssuerPresentationPolicy? pinnedDidWebIssuer,
        out JsonElement verifiedSubject)
    {
        if (pinnedDidWebIssuer is null)
        {
            return JwtVcJsonCredential.TryVerify(credentialJwt, trustedIssuerDid,
                holderDid, credentialType, context, now, out verifiedSubject);
        }

        verifiedSubject = default;
        return string.Equals(trustedIssuerDid, pinnedDidWebIssuer.IssuerDid,
                   StringComparison.Ordinal) &&
            JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                credentialJwt, trustedIssuerDid,
                pinnedDidWebIssuer.VerificationMethodId,
                pinnedDidWebIssuer.PublicKey, pinnedDidWebIssuer.IssuerName,
                pinnedDidWebIssuer.CredentialId, holderDid, credentialType,
                context, now, out verifiedSubject);
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

    private static bool TryReadCredentialExpiry(string credentialJwt, out decimal expiresAt)
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
            // The issuer JWT was already verified above, with its exact type,
            // signature and canonical payload. Preserve fractional NumericDate
            // for presentation expiry rather than rejecting a valid VC1.1 JWT.
            // Historical vc+jwt fractional inputs fail in that prior verifier.
            return JwtVcJsonCredential.TryGetSignedNumericDate(
                document.RootElement, "exp", normative: true, out expiresAt);
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
