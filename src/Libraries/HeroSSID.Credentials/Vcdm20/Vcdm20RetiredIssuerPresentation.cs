using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Retired-issuer policy combined with holder Ed25519 proof and an atomic
/// verifier-owned one-use challenge. A signature is not real-world identity
/// verification, holder consent or business authorization.
/// </summary>
public static class Vcdm20RetiredIssuerPresentation
{
    /// <summary>
    /// Validate a full-disclosure holder-signed direct VC2 presentation and then
    /// independently require active issuer trust or an exact historical JWT pin.
    /// A challenge spent by a valid holder proof cannot be replayed even if
    /// the verifier's independent retirement policy rejects the credential.
    /// </summary>
    public static Vcdm20VerifierPolicyResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        TimeProvider clock, out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        throw new NotSupportedException("Retired-issuer holder proof has not been implemented.");

    /// <summary>
    /// Additionally require an authentic, short-lived private revocation status
    /// from the actual signer; clean issuer status is not proof of live clearance.
    /// </summary>
    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string presentationJwt, string revocationSnapshotJwt,
        Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        TimeProvider clock, out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        throw new NotSupportedException("Retired-issuer holder proof has not been implemented.");
}
