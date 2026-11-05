using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Holder- and recipient-bound direct VC2 full-disclosure profile.
/// No external wallet interoperability, consent attestation, status or business authorization.
/// </summary>
public static partial class Vcdm20JosePresentation
{
    /// <summary>Sign a verifier-request-bound presentation only for an issuer-signed, exact recipient and ID.</summary>
    public static string CreateForAudienceWithIdAndSignedRequest(
        string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedContextUri,
        Uri expectedCredentialId, Uri expectedCredentialAudience,
        string holderDid, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Test-only RED: recipient-bound holder presentation is not implemented.");

    /// <summary>Verify issuer, holder, exact recipient, ID, signed original request and one-use challenge.</summary>
    public static Vcdm20PresentationCheckResult CheckForAudienceWithIdAndSignedRequest(
        string presentationJwt, string signedRequestJwt, string trustedRequestSha256,
        string trustedVerifierDid, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        Uri expectedCredentialId, Uri expectedCredentialAudience,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Test-only RED: recipient-bound holder verification is not implemented.");
    }
}
