using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in issuer-recipient-bound, full-disclosure VC2 holder presentation.
/// Issuer signature, holder key possession and verifier trust policy are separate.
/// Does not provide consent proof, status, real-world identity or authorization.
/// </summary>
public static partial class Vcdm20JosePresentation
{
    /// <summary>
    /// Re-authenticate the signed verifier's type/context-bound request and the
    /// original issuer's exact credential ID and single HTTPS recipient, then
    /// sign a request-hash-bound VP with the actual holder's Ed25519 seed.
    /// The Wallet application must separately obtain informed consent.
    /// </summary>
    public static string CreateForAudienceWithIdAndSignedRequest(
        string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedContextUri,
        Uri expectedCredentialId, Uri expectedCredentialAudience,
        string holderDid, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialAudience);
        if (!string.Equals(expectedAudience, expectedCredentialAudience.AbsoluteUri,
            StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The independently pinned signed credential recipient must be exactly the verifier's request audience.",
                nameof(expectedCredentialAudience));
        }

        return CreateCore(signedRequestJwt, trustedVerifierDid, expectedAudience,
            credentialJwt, expectedCredentialType, expectedContextUri, holderDid,
            holderSeed, clock, bindOriginalRequest: true, expectedCredentialId,
            expectedCredentialAudience);
    }

    /// <summary>
    /// Accept only one issuer- and holder-signed VP for this verifier-owned original
    /// request, exact HTTPS audience and VC ID, consuming the tenant challenge atomically.
    /// An authentic issuer signature is not a revocation or business policy decision.
    /// </summary>
    public static Vcdm20PresentationCheckResult CheckForAudienceWithIdAndSignedRequest(
        string presentationJwt, string signedRequestJwt, string trustedRequestSha256,
        string trustedVerifierDid, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        Uri expectedCredentialId, Uri expectedCredentialAudience,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialAudience);
        verifiedSubject = default;

        // The caller MUST supply its independently retained, exact verifier JWS
        // digest, DID and policy. Neither a holder-supplied JWT nor a valid
        // issuer signature can select a new recipient or spending authority.
        if (!string.Equals(expectedAudience, expectedCredentialAudience.AbsoluteUri,
                StringComparison.Ordinal) ||
            !MatchesPinnedSignedVerifierRequest(
                signedRequestJwt, trustedRequestSha256, trustedVerifierDid,
                verifierTenantId, expectedAudience, expectedNonce,
                expectedCredentialType, expectedContextUri, challenges, clock))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        return CheckCore(presentationJwt, verifierTenantId, expectedAudience,
            expectedNonce, expectedCredentialType, expectedContextUri,
            challenges, clock, trustedRequestSha256, out verifiedSubject,
            out _, out _, expectedCredentialId, expectedCredentialAudience);
    }
}
