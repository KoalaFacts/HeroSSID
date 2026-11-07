using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// An issuer-operated, restricted direct VC2 JOSE issuance path for a pinned
/// did:web Ed25519 assertion method. Issuance is separate from verifier trust
/// enrollment, proof of holder key control and business authorization.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Create a genuine issuer-signed VC2 JWT for one HTTPS recipient. The
    /// operator supplies a previously approved DID/method/public-key binding.
    /// The SDK does not fetch DID documents, enroll trust or own the signing key.
    /// The caller retains responsibility for clearing its private-key buffer.
    /// A signed name, audience or membership value does not grant authority.
    /// </summary>
    public static string CreateForPinnedDidWebIssuerAudienceWithId(
        string issuerDid, string assertionMethodId,
        byte[] issuerPrivateKey, byte[] issuerPublicKey,
        string issuerName, Uri credentialId, Uri audience,
        string holderDid, string credentialType, Uri subjectContextUri,
        JsonElement credentialSubject,
        DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(assertionMethodId);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);
        ArgumentNullException.ThrowIfNull(issuerName);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);

        if (!JwtVcJsonPinnedDidWebIssuerVerifier.IsRestrictedDidWeb(issuerDid) ||
            !(string.Equals(assertionMethodId, issuerDid + "#key-1",
                StringComparison.Ordinal) ||
              string.Equals(assertionMethodId, issuerDid + "#key-2",
                StringComparison.Ordinal)) ||
            issuerPublicKey.Length != 32 ||
            issuerPublicKey.All(static b => b == 0) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !ValidIssuerName(issuerName) ||
            !ValidCredentialId(credentialId) ||
            !ValidAudience(audience) ||
            !ValidContext(subjectContextUri) ||
            !ValidType(credentialType) ||
            validUntil <= validFrom ||
            credentialSubject.ValueKind != JsonValueKind.Object ||
            !HasSubjectId(credentialSubject, holderDid) ||
            StrictJwtReader.HasEmbeddedContext(credentialSubject) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException(
                "Invalid issuer method, signer key, subject, recipient or signed credential policy.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = CredentialHeaderType,
            cty = "vc",
            kid = assertionMethodId
        });
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
            ["type"] = new[] { CredentialBaseType, credentialType },
            ["issuer"] = new { id = issuerDid, name = issuerName },
            ["validFrom"] = FormatDate(validFrom),
            ["validUntil"] = FormatDate(validUntil),
            ["credentialSubject"] = credentialSubject,
            ["id"] = credentialId.AbsoluteUri,
            ["aud"] = audience.AbsoluteUri
        };
        string jwt = Ed25519JwtSigner.CreateSignedJwt(
            header, JsonSerializer.Serialize(claims), issuerPrivateKey);

        // A supplied public key is not trusted by third-party verifiers merely
        // because the issuer provided it. This local check only prevents
        // returning an artifact from the wrong seed or malformed profile.
        if (jwt.Length > MaximumJwtLength ||
            !TryVerifyPinnedDidWebIssuerForAudienceWithId(
                jwt, issuerDid, assertionMethodId, issuerPublicKey, issuerName,
                credentialId, audience, holderDid, credentialType,
                subjectContextUri, validFrom, out _))
        {
            throw new ArgumentException(
                "Signing key does not match the approved public key, or the issued VC2 artifact is invalid.",
                nameof(issuerPrivateKey));
        }

        return jwt;
    }
}
