using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in full-disclosure holder proof plus an independently pinned exact
/// issuer-signed membership claim policy. Does not grant business authority.
/// </summary>
public static class Vcdm20SignedClaimPresentation
{
    /// <summary>
    /// Verifies one-use holder possession and the unchanged original VC2 JWT
    /// against a separately supplied credential ID and exact signed claims.
    /// Revocation, user consent and external identity remain caller responsibilities.
    /// </summary>
    public static Vcdm20PresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredSubjectClaims,
        TimeProvider clock, out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("RED: holder-bound signed claim verification not implemented.");
    }
}
