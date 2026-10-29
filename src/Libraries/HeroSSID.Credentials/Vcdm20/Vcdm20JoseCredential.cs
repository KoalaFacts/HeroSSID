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
public static class Vcdm20JoseCredential
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
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil)
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
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            validUntil <= validFrom ||
            credentialSubject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(credentialSubject, holderDid) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException("Invalid VC2 issuer, holder, policy, subject, seed or validity interval.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = CredentialHeaderType,
            kid = KeyId(issuerDid)
        });
        string payload = JsonSerializer.Serialize(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
            ["type"] = new[] { CredentialBaseType, credentialType },
            ["issuer"] = issuerDid,
            ["validFrom"] = FormatDate(validFrom),
            ["validUntil"] = FormatDate(validUntil),
            ["credentialSubject"] = credentialSubject
        });
        string jwt = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerPrivateKey);

        // Reject mismatched issuer seeds and ambiguous serialized claims before release.
        if (jwt.Length > MaximumJwtLength ||
            !TryVerify(jwt, issuerDid, holderDid, credentialType,
                subjectContextUri, validFrom, out _))
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
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var issuerPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolderDid, out _) ||
            !ValidType(expectedCredentialType) ||
            !ValidContext(expectedSubjectContextUri) ||
            !StrictJwtReader.TryRead(jwt, CredentialHeaderType, MaximumJwtLength,
                out var credential, KeyId(trustedIssuerDid)) ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, issuerPublicKey) ||
            credential.TryGetProperty("vc", out _) ||
            credential.TryGetProperty("vp", out _) ||
            !StrictJwtReader.TryGetString(credential, "issuer", out var signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !HasExactArray(credential, "@context", BaseContext,
                expectedSubjectContextUri.AbsoluteUri) ||
            !HasExactArray(credential, "type", CredentialBaseType, expectedCredentialType) ||
            !TryReadDate(credential, "validFrom", out var validFrom) ||
            !TryReadDate(credential, "validUntil", out var validUntil) ||
            validUntil <= validFrom || now < validFrom || now >= validUntil ||
            !credential.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(subject, expectedHolderDid) ||
            Encoding.UTF8.GetByteCount(subject.GetRawText()) > MaximumSubjectBytes)
        {
            return false;
        }

        verifiedSubject = subject.Clone();
        return true;
    }

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
