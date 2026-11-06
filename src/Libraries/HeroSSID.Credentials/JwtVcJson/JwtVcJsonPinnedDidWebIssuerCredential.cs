using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Explicit opt-in issuance of genuine VC Data Model 1.1 jwt_vc_json credentials
/// using a separately configured did:web Ed25519 assertion key. DID publication,
/// domain ownership and verifier trust enrollment remain outside this SDK.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerCredential
{
    private const int MaximumJwtLength = 65_536;
    private const int MaximumSubjectBytes = 16_384;
    private const long MaximumValiditySeconds = 900;

    /// <summary>
    /// Sign a single issuer-named VC1.1 JWT with an exact HTTPS credential ID and
    /// a caller-supplied did:web assertion method. The expected public key must
    /// correspond to the signing seed; a verifier must independently pin that
    /// method and public key. This does not prove issuer identity or authority.
    /// </summary>
    public static string CreateWithIssuerNameAndId(
        string issuerDid, string assertionMethodId, byte[] expectedSigningPublicKey,
        string holderDid, string credentialType, Uri subjectContextUri,
        JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil,
        string issuerName, Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(assertionMethodId);
        ArgumentNullException.ThrowIfNull(expectedSigningPublicKey);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(issuerName);
        ArgumentNullException.ThrowIfNull(credentialId);

        // Match the existing VC1.1 whole-second issuer contract: never widen
        // the requested validity window by rounding start down or expiry up.
        long issued = validFrom.ToUnixTimeSeconds();
        if (validFrom.UtcTicks % TimeSpan.TicksPerSecond != 0)
        {
            issued++;
        }

        long expires = validUntil.ToUnixTimeSeconds();
        if (expectedSigningPublicKey.Length != 32 ||
            expectedSigningPublicKey.All(static b => b == 0) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            issued < 0 || expires <= issued ||
            expires - issued > MaximumValiditySeconds ||
            issuerName.Length is < 1 or > 128 ||
            string.IsNullOrWhiteSpace(issuerName) ||
            issuerName.Any(char.IsControl) ||
            credentialSubject.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException("Invalid did:web signing key, issuer metadata, subject or bounded validity.");
        }

        // The original compact JWT is the credential. Never rewrite an
        // existing did:key token or copy any untrusted issuer/key assertion
        // from a credential as a verifier trust policy.
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "JWT",
            kid = assertionMethodId
        });
        var payloadClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = issuerDid,
            ["sub"] = holderDid,
            ["iat"] = issued,
            ["nbf"] = issued,
            ["exp"] = expires,
            ["jti"] = credentialId.AbsoluteUri,
            ["vc"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["@context"] = new[]
                {
                    "https://www.w3.org/2018/credentials/v1",
                    subjectContextUri.AbsoluteUri
                },
                ["type"] = new[] { "VerifiableCredential", credentialType },
                ["issuer"] = new { id = issuerDid, name = issuerName },
                ["credentialSubject"] = credentialSubject
            }
        };
        string signed = Ed25519JwtSigner.CreateSignedJwt(
            header, JsonSerializer.Serialize(payloadClaims), issuerPrivateKey);

        // Independently apply the same exact method/public-key, issuer-name,
        // credential-ID, holder and vocabulary checks the recipient uses.
        // In particular, a mismatched seed cannot issue an apparently trusted
        // credential and malformed signed input must never escape as valid.
        if (signed.Length > MaximumJwtLength ||
            !JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                signed, issuerDid, assertionMethodId, expectedSigningPublicKey,
                issuerName, credentialId, holderDid, credentialType,
                subjectContextUri, DateTimeOffset.FromUnixTimeSeconds(issued), out _))
        {
            throw new ArgumentException(
                "The signing seed does not match the configured issuer key or the VC is invalid.",
                nameof(issuerPrivateKey));
        }

        return signed;
    }
}
