using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in JWT-secured W3C VC 1.1 JSON profile for the OpenID4VP
/// jwt_vc_json credential format. Not the distinct VCDM 2.0 direct payload.
/// </summary>
public static class JwtVcJsonCredential
{
    /// <summary>Issuer signs the complete credential using its own Ed25519 key.</summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        throw new NotSupportedException("jwt_vc_json issuance is not yet implemented.");

    /// <summary>Offline issuer-signature and independently pinned credential policy verification.</summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject) =>
        throw new NotSupportedException("jwt_vc_json verification is not yet implemented.");
}
