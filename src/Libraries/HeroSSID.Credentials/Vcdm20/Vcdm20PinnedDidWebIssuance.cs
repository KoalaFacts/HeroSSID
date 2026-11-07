using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// An issuer-operated, restricted direct VC2 JOSE issuance path for a pinned
/// did:web Ed25519 assertion method. Issuance is separate from verifier trust
/// enrollment, proof of holder key control and business authorization.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Create an issuer-signed VC2 JWT for a single HTTPS relying-party recipient.
    /// The caller owns the signing seed, approved public key and issuer DID;
    /// neither private-key custody nor trust enrollment is performed here.
    /// </summary>
    public static string CreateForPinnedDidWebIssuerAudienceWithId(
        string issuerDid, string assertionMethodId,
        byte[] issuerPrivateKey, byte[] issuerPublicKey,
        string issuerName, Uri credentialId, Uri audience,
        string holderDid, string credentialType, Uri subjectContextUri,
        JsonElement credentialSubject,
        DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        throw new NotSupportedException("Issuer-operated did:web VC2 issuance is not implemented.");
}
