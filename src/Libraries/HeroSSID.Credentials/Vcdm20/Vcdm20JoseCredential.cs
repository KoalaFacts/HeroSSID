using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in, database-independent VC Data Model 2.0 JWT/JWS wire profile.
/// The issuer signs the credential; holders only retain and present it.
/// </summary>
public static class Vcdm20JoseCredential
{
    /// <summary>Issue a directly encoded VC 2.0 JSON object in an Ed25519 JWS.</summary>
    public static string Create(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        throw new NotSupportedException("VC Data Model 2.0 JOSE issuance is not implemented.");
    }

    /// <summary>
    /// Verify a real issuer signature and a bounded VC 2.0 profile against the
    /// relying party's independent trust and subject/context/type policy.
    /// No claims are exposed on failure; verification does not grant authority.
    /// </summary>
    public static bool TryVerify(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return false;
    }
}
