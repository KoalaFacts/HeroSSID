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
    private const string JwtType = "vc+jwt";
    private const int MaximumJwtLength = 65_536;
    private const int MaximumSubjectBytes = 16_384;
    private const long MaximumValiditySeconds = 900;

    /// <summary>
    /// Sign a short-lived, fully disclosed JWT VC 1.1 with the issuer's own Ed25519 seed.
    /// Subject vocabulary is controlled by a versioned HTTPS context pinned by the verifier.
    /// A signature proves issuer-key control, NOT real-world identity, authorization or
    /// control of the holder's key. Caller must protect and erase the seed.
    /// </summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        long issued = validFrom.ToUnixTimeSeconds();
        long expires = validUntil.ToUnixTimeSeconds();
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !ValidType(credentialType) ||
            !ValidContext(subjectContextUri) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            validFrom.UtcTicks % TimeSpan.TicksPerSecond != 0 ||
            validUntil.UtcTicks % TimeSpan.TicksPerSecond != 0 ||
            issued < 0 || expires <= issued ||
            expires - issued > MaximumValiditySeconds ||
            credentialSubject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(credentialSubject, holderDid) ||
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
        string payload = JsonSerializer.Serialize(new
        {
            iss = issuerDid,
            sub = holderDid,
            iat = issued,
            nbf = issued,
            exp = expires,
            vc = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
                ["type"] = new[] { BaseType, credentialType },
                ["credentialSubject"] = credentialSubject
            }
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerPrivateKey);

        // Check the actual cryptographic result against the self-certifying issuer DID,
        // including unique nested JSON properties. Wrong-key or malformed output
        // must never escape this API as a purported credential.
        if (signed.Length > MaximumJwtLength ||
            !TryVerify(signed, issuerDid, holderDid, credentialType,
                subjectContextUri, validFrom, out _))
        {
            throw new ArgumentException("The seed does not control the issuer DID or the VC is ambiguous/oversized.",
                nameof(issuerPrivateKey));
        }

        return signed;
    }

    /// <summary>
    /// Independently verify the actual Ed25519 issuer signature and pinned issuer,
    /// holder, type, HTTPS vocabulary and 15-minute validity, before releasing claims.
    /// Does NOT establish holder possession, consent, revocation or business authority.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
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
            !StrictJwtReader.TryRead(jwt, JwtType, MaximumJwtLength,
                out var payload, KeyId(trustedIssuerDid)) ||
            payload.EnumerateObject().Count() != 6 ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, issuerPublicKey) ||
            !StrictJwtReader.TryGetString(payload, "iss", out var signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "sub", out var signedSubject) ||
            !string.Equals(signedSubject, expectedHolderDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out var issued) ||
            !StrictJwtReader.TryGetTimestamp(payload, "nbf", out var notBefore) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out var expires) ||
            issued != notBefore || expires <= issued ||
            expires - issued > MaximumValiditySeconds ||
            notBefore > now.ToUnixTimeSeconds() || expires <= now.ToUnixTimeSeconds() ||
            !payload.TryGetProperty("vc", out var vc) ||
            vc.ValueKind != JsonValueKind.Object || vc.EnumerateObject().Count() != 3 ||
            !HasExactArray(vc, "@context", BaseContext, expectedSubjectContextUri.AbsoluteUri) ||
            !HasExactArray(vc, "type", BaseType, expectedCredentialType) ||
            !vc.TryGetProperty("credentialSubject", out var subject) ||
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
