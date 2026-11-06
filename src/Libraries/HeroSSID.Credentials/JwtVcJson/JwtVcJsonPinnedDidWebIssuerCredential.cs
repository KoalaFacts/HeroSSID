using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Explicit opt-in issuance of genuine VC Data Model 1.1 jwt_vc_json credentials
/// using a separately configured did:web Ed25519 assertion key. DID publication,
/// domain ownership and verifier trust enrollment remain outside this SDK.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerCredential
{
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
        throw new NotSupportedException("Test-first: did:web VC1.1 JWT issuance is not yet implemented.");
    }
}
