using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// A verifier's single-use holder admission outcome. Claims are undefined on failure.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebOnlineAdmissionResponse(
    JwtVcJsonPinnedDidWebIssuerAdmissionResult Result, JsonElement VerifiedSubject);

/// <summary>
/// Optional verifier flow: fetch an issuer-signed exact-credential observation
/// from an independently pinned endpoint, then apply BOTH verifier-local denial
/// and issuer revocation policy to one genuine holder presentation.
/// This is not a standards-based status service or live non-revocation proof.
/// </summary>
public static class JwtVcJsonPinnedDidWebOnlineAdmission
{
    /// <summary>
    /// Fail closed without disclosing claims. A successful authenticated holder
    /// proof consumes one challenge when the composite admission gate is reached.
    /// </summary>
    public static Task<JwtVcJsonPinnedDidWebOnlineAdmissionResponse> CheckAsync(
        Uri independentlyPinnedStatusUri, HttpClient http,
        string originalCredentialJwt, string presentationJwt,
        Guid verifierTenantId, string expectedAudience, string expectedNonce,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(new JwtVcJsonPinnedDidWebOnlineAdmissionResponse(
            JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, default));
}
