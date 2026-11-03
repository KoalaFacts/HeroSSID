using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Strict opt-in W3C VC Data Model 1.1 JWT-VC credential profile as used by
/// OpenID4VP 1.0's jwt_vc_json format. This is NOT VCDM 2.0 JOSE, the legacy
/// HeroSSID vc.context representation, an OpenID4VP exchange, or a wallet.
/// </summary>
public static class JwtVcJsonCredential
{
    private const string BaseContext = "https://www.w3.org/2018/credentials/v1";
    private const string BaseType = "VerifiableCredential";
    // W3C VC Data Model 1.1 Recommendation §6.3.1 requires typ=JWT if present.
    // Retain verification of the previously issued HeroSSID vc+jwt header as a
    // bounded legacy input, without presenting it as VC1.1-conformant output.
    private const string JwtType = "JWT";
    private const string LegacyJwtType = "vc+jwt";
    private const int MaximumJwtLength = 65_536;
    private const int MaximumSubjectBytes = 16_384;
    private const long MaximumValiditySeconds = 900;

    /// <summary>
    /// Opt-in issuance of a VC Data Model 1.1 credential with an issuer-assigned
    /// HTTPS identifier in the signed JWT jti claim. This identifier is not
    /// an authorization or identity attestation and is never dereferenced.
    /// </summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil, Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, credentialId);
    }

    /// <summary>
    /// Verify issuer-signed claims and expose the exact authenticated JWT jti
    /// only after every verification condition succeeds, or null on failure.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject, out string? verifiedCredentialId)
        => TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject, out verifiedCredentialId);

    /// <summary>
    /// Sign a short-lived, fully disclosed JWT VC 1.1 with the issuer's own Ed25519 seed.
    /// Subject vocabulary is controlled by a versioned HTTPS context pinned by the verifier.
    /// A signature proves issuer-key control, NOT real-world identity, authorization or
    /// control of the holder's key. Caller must protect and erase the seed.
    /// </summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, null);

    private static string CreateCore(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil, Uri? credentialId)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        // JWT NumericDate uses whole seconds. Round the start UP and the end DOWN:
        // the signed credential must never become valid before the requested start
        // or remain valid after the requested end. Reject windows that disappear.
        long issued = validFrom.ToUnixTimeSeconds();
        if (validFrom.UtcTicks % TimeSpan.TicksPerSecond != 0)
        {
            issued++;
        }

        long expires = validUntil.ToUnixTimeSeconds();
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !ValidType(credentialType) ||
            !ValidContext(subjectContextUri) ||
            (credentialId is not null && !ValidCredentialId(credentialId)) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            issued < 0 || expires <= issued ||
            expires - issued > MaximumValiditySeconds ||
            credentialSubject.ValueKind != JsonValueKind.Object ||
            // VC1.1 JWT sub is the authoritative subject ID. Do not invent a
            // nested id when the issuer intentionally leaves it out; reject
            // an explicit conflicting value exactly as the verifier does.
            !HasBoundSubject(credentialSubject, holderDid, isNormativeJwt: true) ||
            StrictJwtReader.HasEmbeddedContext(credentialSubject) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException("Invalid JWT VC 1.1 key, context, subject, vocabulary or bounded validity.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = JwtType,
            kid = KeyId(issuerDid)
        });
        var payloadClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = issuerDid,
            ["sub"] = holderDid,
            ["iat"] = issued,
            ["nbf"] = issued,
            ["exp"] = expires
        };
        if (credentialId is not null)
        {
            payloadClaims["jti"] = credentialId.AbsoluteUri;
        }

        payloadClaims["vc"] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
            ["type"] = new[] { BaseType, credentialType },
            ["credentialSubject"] = credentialSubject
        };
        string payload = JsonSerializer.Serialize(payloadClaims);
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerPrivateKey);

        // Check the actual cryptographic result against the self-certifying issuer DID,
        // including unique nested JSON properties. Wrong-key or malformed output
        // must never escape this API as a purported credential.
        if (signed.Length > MaximumJwtLength ||
            !TryVerify(signed, issuerDid, holderDid, credentialType,
                subjectContextUri, DateTimeOffset.FromUnixTimeSeconds(issued), out _))
        {
            throw new ArgumentException("The seed does not control the issuer DID or the VC is ambiguous/oversized.",
                nameof(issuerPrivateKey));
        }

        return signed;
    }

    /// <summary>
    /// Independently verify the actual Ed25519 issuer signature and pinned issuer,
    /// holder, type, HTTPS vocabulary and 15-minute validity, before releasing claims.
    /// Also accepts independently signed VC1.1 JWTs with typ=JWT, an omitted
    /// optional kid, bounded HTTPS jti and no iat (or iat preceding nbf by at
    /// most 15 minutes). A present kid MUST match the pinned issuer. Existing
    /// HeroSSID typ=vc+jwt credentials remain readable as legacy input only.
    /// Does NOT establish holder possession, consent, revocation or business authority.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject) =>
        TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject, out _);

    private static bool TryVerifyCore(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject, out string? verifiedCredentialId)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;
        verifiedCredentialId = null;

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var issuerPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolderDid, out _) ||
            !ValidType(expectedCredentialType) ||
            !ValidContext(expectedSubjectContextUri) ||
            !TryReadSupportedCredentialJwt(jwt, trustedIssuerDid, out var payload, out bool isNormativeJwt) ||
            !HasSupportedClaims(payload) ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, issuerPublicKey) ||
            !StrictJwtReader.TryGetString(payload, "iss", out var signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "sub", out var signedSubject) ||
            !string.Equals(signedSubject, expectedHolderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetTimestamp(payload, "nbf", out var notBefore) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out var expires) ||
            !HasValidOptionalIssuedAt(payload, notBefore) ||
            !HasValidOptionalCredentialId(payload) ||
            expires <= notBefore || expires - notBefore > MaximumValiditySeconds ||
            notBefore > now.ToUnixTimeSeconds() || expires <= now.ToUnixTimeSeconds() ||
            !payload.TryGetProperty("vc", out var vc) ||
            vc.ValueKind != JsonValueKind.Object || vc.EnumerateObject().Count() != 3 ||
            !HasExactArray(vc, "@context", BaseContext, expectedSubjectContextUri.AbsoluteUri) ||
            !HasExactArray(vc, "type", BaseType, expectedCredentialType) ||
            !vc.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !HasBoundSubject(subject, expectedHolderDid, isNormativeJwt) ||
            StrictJwtReader.HasEmbeddedContext(subject) ||
            Encoding.UTF8.GetByteCount(subject.GetRawText()) > MaximumSubjectBytes)
        {
            return false;
        }

        verifiedSubject = subject.Clone();
        verifiedCredentialId = payload.TryGetProperty("jti", out var identifier)
            ? identifier.GetString()
            : null;
        return true;
    }

    private static bool TryReadSupportedCredentialJwt(string jwt, string issuerDid,
        out JsonElement payload, out bool isNormativeJwt)
    {
        // W3C VC1.1 REC §6.3.1 makes typ optional (if present, JWT), and
        // kid optional. Both still require an independently pinned Ed25519
        // issuer; the legacy vc+jwt form keeps its mandatory kid and typ. The
        // verifier-supplied did:key always supplies the signature key.
        // Legacy vc+jwt MUST continue to have the exact issuer kid.
        isNormativeJwt =
            StrictJwtReader.TryRead(jwt, JwtType, MaximumJwtLength,
                out payload, KeyId(issuerDid), allowMissingType: true) ||
            StrictJwtReader.TryRead(jwt, JwtType, MaximumJwtLength,
                out payload, allowMissingType: true);
        return isNormativeJwt ||
            StrictJwtReader.TryRead(jwt, LegacyJwtType, MaximumJwtLength,
                out payload, KeyId(issuerDid));
    }

    private static bool HasBoundSubject(JsonElement subject, string holderDid, bool isNormativeJwt)
    {
        // JWT sub represents credentialSubject.id in VC1.1. The duplicate
        // nested field MAY be omitted for the normative JWT only. If explicitly
        // present, including null or an empty string, it MUST match the independently
        // pinned holder; never let a signed conflict be silently overwritten.
        if (subject.TryGetProperty("id", out _))
        {
            return HasSubjectId(subject, holderDid);
        }

        return isNormativeJwt;
    }

    // W3C VC 1.1 maps the credential id into JWT jti. OpenID4VP's
    // jwt_vc_json example omits iat altogether. Recognize only these
    // two known optional claims; fail closed on any other payload members.
    private static bool HasSupportedClaims(JsonElement payload) =>
        payload.EnumerateObject().Count() == 5 +
        (payload.TryGetProperty("iat", out _) ? 1 : 0) +
        (payload.TryGetProperty("jti", out _) ? 1 : 0);

    private static bool HasValidOptionalIssuedAt(JsonElement payload, long notBefore)
    {
        // JWT iat describes signature issue time, not credential validity.
        // It can precede nbf, but is never a proof of historical signing.
        // A bounded window prevents accepting arbitrary backdated timestamps.
        return !payload.TryGetProperty("iat", out _) ||
            (StrictJwtReader.TryGetTimestamp(payload, "iat", out long issued) &&
                issued <= notBefore && issued >= notBefore - MaximumValiditySeconds);
    }

    private static bool HasValidOptionalCredentialId(JsonElement payload)
    {
        if (!payload.TryGetProperty("jti", out _))
        {
            return true;
        }

        // Signed identifiers are never dereferenced or treated as authority.
        return StrictJwtReader.TryGetString(payload, "jti", out string id) &&
            id.Length <= 2_048 &&
            Uri.TryCreate(id, UriKind.Absolute, out Uri? uri) &&
            ValidCredentialId(uri);
    }

    private static bool ValidCredentialId(Uri uri) =>
        uri.IsAbsoluteUri &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        uri.UserInfo.Length == 0 &&
        uri.AbsoluteUri.Length <= 2_048;

    private static bool HasExactArray(JsonElement element, string name, string first, string second)
    {
        if (!element.TryGetProperty(name, out var values) ||
            values.ValueKind != JsonValueKind.Array || values.GetArrayLength() != 2)
        {
            return false;
        }

        return values[0].ValueKind == JsonValueKind.String &&
            values[1].ValueKind == JsonValueKind.String &&
            string.Equals(values[0].GetString(), first, StringComparison.Ordinal) &&
            string.Equals(values[1].GetString(), second, StringComparison.Ordinal);
    }

    private static bool HasSubjectId(JsonElement subject, string holderDid) =>
        StrictJwtReader.TryGetString(subject, "id", out var id) &&
        string.Equals(id, holderDid, StringComparison.Ordinal);

    private static bool ValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Fragment) &&
        uri.AbsoluteUri.Length <= 2048;

    private static bool ValidType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        !string.Equals(type, BaseType, StringComparison.Ordinal);

    private static string KeyId(string issuerDid) =>
        issuerDid + "#" + issuerDid["did:key:".Length..];
}
