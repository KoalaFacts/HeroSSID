using System.Globalization;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in direct-payload VC Data Model 2.0 JOSE profile, using real Ed25519
/// did:key signatures. Distinct from legacy nested-vc JWTs; no database,
/// wallet key escrow, JSON-LD expansion, status lookup or authorization.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    private const string BaseContext = "https://www.w3.org/ns/credentials/v2";
    private const string CredentialHeaderType = "vc+jwt";
    private const string CredentialBaseType = "VerifiableCredential";
    private const int MaximumJwtLength = 65_536;
    private const int MaximumSubjectBytes = 16_384;
    private static readonly string[] DateFormats =
    [
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"
    ];

    /// <summary>
    /// Issue a directly encoded VC 2.0 payload (not a legacy JWT 'vc' claim).
    /// The issuer must control its DID seed; the holder receives only the
    /// signed credential. The caller owns and clears the private-key buffer.
    /// Extra subject terms MUST be defined by the caller's versioned context.
    /// </summary>
    public static string Create(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, null);

    private static string CreateCore(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil,
        Uri? credentialId, string? issuerName = null, Uri? audience = null)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !ValidType(credentialType) ||
            !ValidContext(subjectContextUri) ||
            (issuerName is not null && !ValidIssuerName(issuerName)) ||
            (credentialId is not null && !ValidCredentialId(credentialId)) ||
            (audience is not null &&
                (credentialId is null || issuerName is not null || !ValidAudience(audience))) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            validUntil <= validFrom ||
            credentialSubject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(credentialSubject, holderDid) ||
            StrictJwtReader.HasEmbeddedContext(credentialSubject) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException("Invalid VC2 issuer, holder, policy, subject, seed or validity interval.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = CredentialHeaderType,
            cty = "vc",
            kid = KeyId(issuerDid)
        });
        var credentialClaims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
            ["type"] = new[] { CredentialBaseType, credentialType },
            ["issuer"] = issuerName is null ? (object)issuerDid : new { id = issuerDid, name = issuerName },
            ["validFrom"] = FormatDate(validFrom),
            ["validUntil"] = FormatDate(validUntil),
            ["credentialSubject"] = credentialSubject
        };
        if (credentialId is not null)
        {
            // Signed VC 2.0 top-level id, distinct from credentialSubject.id.
            credentialClaims["id"] = credentialId.AbsoluteUri;
        }

        if (audience is not null)
        {
            // The exact registered JWT aud claim is signed into the original VC2 token.
            credentialClaims["aud"] = audience.AbsoluteUri;
        }

        string payload = JsonSerializer.Serialize(credentialClaims);
        string jwt = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerPrivateKey);

        // Reject mismatched issuer seeds and ambiguous serialized claims before release.
        bool verified = audience is not null
            ? TryVerifyForAudienceWithId(jwt, issuerDid, holderDid, credentialType,
                subjectContextUri, credentialId!, audience, validFrom, out _)
            : issuerName is not null
            ? credentialId is not null
                ? TryVerifyNamedIssuerWithId(jwt, issuerDid, issuerName, holderDid,
                    credentialType, subjectContextUri, credentialId, validFrom, out _)
                : TryVerifyNamedIssuer(jwt, issuerDid, issuerName, holderDid,
                    credentialType, subjectContextUri, validFrom, out _)
            : credentialId is null
                ? TryVerify(jwt, issuerDid, holderDid, credentialType,
                    subjectContextUri, validFrom, out _)
                : TryVerifyWithId(jwt, issuerDid, holderDid, credentialType,
                    subjectContextUri, validFrom, out _, out _);
        if (jwt.Length > MaximumJwtLength || !verified)
        {
            throw new ArgumentException("The supplied issuer key or credential data cannot produce a valid VC2 artifact.", nameof(issuerPrivateKey));
        }

        return jwt;
    }

    /// <summary>
    /// Verify an issuer-signed direct VC 2.0 JWT against independently pinned
    /// did:key issuer, holder, claim vocabulary and credential type.
    /// Outputs claims only after signature, profile and validity checks pass.
    /// A valid result does NOT imply identity vetting, key-holder proof,
    /// revocation, JSON-LD semantic conformance or business authorization.
    /// </summary>
    public static bool TryVerify(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject) =>
        TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject, out _, false);

    private static bool TryVerifyCore(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject,
        out string? verifiedCredentialId, bool requiresCredentialId,
        string? expectedIssuerName = null, Uri? expectedCredentialId = null,
        Uri? expectedAudience = null)
    {
        verifiedCredentialId = null;
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var issuerPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolderDid, out _) ||
            !ValidType(expectedCredentialType) ||
            !ValidContext(expectedSubjectContextUri) ||
            !StrictJwtReader.TryRead(jwt, CredentialHeaderType, MaximumJwtLength,
                out var credential, KeyId(trustedIssuerDid), "vc") ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, issuerPublicKey) ||
            // The existing profile implements six direct VC2 members; the
            // opt-in id profile implements exactly seven. Neither enforces
            // general credentialStatus,
            // proof or evidence semantics; do not authenticate and silently ignore
            // unimplemented signed policy fields before returning subject claims.
            credential.EnumerateObject().Count() !=
                (requiresCredentialId ? 7 : 6) + (expectedAudience is null ? 0 : 1) ||
            (expectedAudience is not null &&
                (!StrictJwtReader.TryGetString(credential, "aud", out string signedAudience) ||
                 !ValidCanonicalAudience(signedAudience) ||
                 !string.Equals(signedAudience, expectedAudience.AbsoluteUri,
                     StringComparison.Ordinal))) ||
            (requiresCredentialId &&
                (!StrictJwtReader.TryGetString(credential, "id", out string signedId) ||
                 !ValidCanonicalCredentialId(signedId) ||
                 (expectedCredentialId is not null &&
                     !string.Equals(signedId, expectedCredentialId.AbsoluteUri,
                         StringComparison.Ordinal)))) ||
            credential.TryGetProperty("vc", out _) ||
            credential.TryGetProperty("vp", out _) ||
            !MatchesExpectedIssuer(credential, trustedIssuerDid, expectedIssuerName) ||
            !HasExactArray(credential, "@context", BaseContext,
                expectedSubjectContextUri.AbsoluteUri) ||
            !HasExactArray(credential, "type", CredentialBaseType, expectedCredentialType) ||
            !TryReadDate(credential, "validFrom", out var validFrom) ||
            !TryReadDate(credential, "validUntil", out var validUntil) ||
            validUntil <= validFrom || now < validFrom || now >= validUntil ||
            !credential.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(subject, expectedHolderDid) ||
            StrictJwtReader.HasEmbeddedContext(subject) ||
            Encoding.UTF8.GetByteCount(subject.GetRawText()) > MaximumSubjectBytes)
        {
            return false;
        }

        verifiedSubject = subject.Clone();
        verifiedCredentialId = requiresCredentialId
            ? credential.GetProperty("id").GetString() : null;
        return true;
    }

    /// <summary>
    /// Opt-in VCDM 2.0 direct JOSE credential with an issuer-signed credential
    /// identifier (the VC's top-level id, not the subject id). The issuer owns
    /// the identifier; it is not a trust anchor or a revocation check.
    /// </summary>
    public static string CreateWithId(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom,
        DateTimeOffset validUntil, Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, credentialId);
    }

    /// <summary>
    /// Opt-in verification of the original signed VCDM 2.0 credential id
    /// against independently pinned issuer, holder, context, type and validity.
    /// Never disclose either id or subject if policy or signature fails.
    /// </summary>
    public static bool TryVerifyWithId(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject,
        out string? verifiedCredentialId)
        => TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject,
            out verifiedCredentialId, true);

    /// <summary>
    /// Opt-in VCDM 2.0 issuer object with id and descriptive name, genuinely
    /// signed by the issuer's Ed25519 seed. Name is NOT legal identity.
    /// </summary>
    public static string CreateWithNamedIssuer(
        string issuerDid, string issuerName, string holderDid,
        string credentialType, Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        ArgumentNullException.ThrowIfNull(issuerName);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil,
            credentialId: null, issuerName: issuerName);
    }

    /// <summary>
    /// Require independently pinned issuer DID and exact signed descriptive
    /// name; legacy string-only verification remains unchanged and strict.
    /// Does not establish remote issuer enrollment or business authorization.
    /// </summary>
    public static bool TryVerifyNamedIssuer(
        string jwt, string trustedIssuerDid, string expectedIssuerName,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return ValidIssuerName(expectedIssuerName) &&
            TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid,
                expectedCredentialType, expectedSubjectContextUri, now,
                out verifiedSubject, out _, requiresCredentialId: false,
                expectedIssuerName: expectedIssuerName);
    }

    /// <summary>
    /// Opt-in directly signed VC2 named issuer and credential id combination.
    /// The issuer's descriptive name is not real-world identity evidence.
    /// </summary>
    public static string CreateWithNamedIssuerAndId(
        string issuerDid, string issuerName, string holderDid,
        string credentialType, Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil,
        Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(issuerName);
        ArgumentNullException.ThrowIfNull(credentialId);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil,
            credentialId, issuerName);
    }

    /// <summary>
    /// Release claims only when independently pinned issuer DID, issuer name
    /// and original signed credential id all match the authentic JWT.
    /// </summary>
    public static bool TryVerifyNamedIssuerWithId(
        string jwt, string trustedIssuerDid, string expectedIssuerName,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, Uri expectedCredentialId,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return ValidIssuerName(expectedIssuerName) &&
            ValidCredentialId(expectedCredentialId) &&
            TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid,
                expectedCredentialType, expectedSubjectContextUri, now,
                out verifiedSubject, out _, requiresCredentialId: true,
                expectedIssuerName: expectedIssuerName,
                expectedCredentialId: expectedCredentialId);
    }

    private static bool MatchesExpectedIssuer(
        JsonElement credential, string trustedIssuerDid, string? expectedIssuerName)
    {
        if (expectedIssuerName is null)
        {
            return StrictJwtReader.TryGetString(credential, "issuer", out string issuer) &&
                string.Equals(issuer, trustedIssuerDid, StringComparison.Ordinal);
        }

        if (!credential.TryGetProperty("issuer", out JsonElement descriptor) ||
            descriptor.ValueKind != JsonValueKind.Object ||
            descriptor.EnumerateObject().Count() != 2 ||
            !StrictJwtReader.TryGetString(descriptor, "id", out string issuerId) ||
            !StrictJwtReader.TryGetString(descriptor, "name", out string issuerName) ||
            !ValidIssuerName(issuerName))
        {
            return false;
        }

        return string.Equals(issuerId, trustedIssuerDid, StringComparison.Ordinal) &&
            string.Equals(issuerName, expectedIssuerName, StringComparison.Ordinal);
    }

    internal static bool ValidIssuerName(string? issuerName) =>
        !string.IsNullOrWhiteSpace(issuerName) &&
        issuerName.Length <= 128 &&
        string.Equals(issuerName.Trim(), issuerName, StringComparison.Ordinal) &&
        !issuerName.Any(char.IsControl);

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

    private static bool TryReadDate(JsonElement value, string name, out DateTimeOffset date)
    {
        date = default;
        return StrictJwtReader.TryGetString(value, name, out var timestamp) &&
            DateTimeOffset.TryParseExact(timestamp, DateFormats,
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal, out date);
    }

    private static string FormatDate(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture);

    private static string KeyId(string issuerDid) =>
        issuerDid + "#" + issuerDid["did:key:".Length..];

    internal static bool ValidCanonicalCredentialId(string id) =>
        id.Length <= 2_048 &&
        Uri.TryCreate(id, UriKind.Absolute, out Uri? uri) &&
        ValidCredentialId(uri) &&
        string.Equals(uri.AbsoluteUri, id, StringComparison.Ordinal);

    internal static bool ValidCanonicalAudience(string audience) =>
        audience.Length <= 2_048 &&
        Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) &&
        ValidAudience(uri) &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static bool ValidAudience(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Fragment) &&
        uri.AbsoluteUri.Length <= 2_048 &&
        string.Equals(uri.OriginalString, uri.AbsoluteUri, StringComparison.Ordinal);

    private static bool ValidCredentialId(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        uri.AbsoluteUri.Length <= 2_048;

    private static bool ValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) &&
        uri.AbsoluteUri.Length <= 2048;

    private static bool ValidType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        !string.Equals(type, CredentialBaseType, StringComparison.Ordinal);
}
