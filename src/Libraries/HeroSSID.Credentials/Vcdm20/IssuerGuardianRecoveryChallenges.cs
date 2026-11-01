using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifier-owned, purpose-separated one-use challenges for issuer guardian
/// recovery. Verification never enrolls or authorizes the successor issuer.
/// </summary>
public static class IssuerGuardianRecoveryChallenges
{
    /// <summary>Issue a bounded, tenant-owned challenge for one old issuer.</summary>
    public static PresentationChallenge Issue(IPresentationChallengeStore store,
        Guid verifierTenantId, string trustedPreviousIssuerDid, Uri verifierAudience,
        TimeSpan? lifetime = null) => throw new NotSupportedException();

    /// <summary>
    /// Check genuine guardian and successor signatures, then consume the
    /// verifier's recovery-only nonce exactly once before disclosing the
    /// proposed successor DID. Organizational recovery remains independent.
    /// </summary>
    public static bool TryVerifyAndConsume(IPresentationChallengeStore store,
        Guid verifierTenantId, string evidenceJson, string trustedPreviousIssuerDid,
        IReadOnlyCollection<string> trustedGuardianDids, int requiredGuardianSignatures,
        Uri verifierAudience, string expectedNonce, TimeProvider clock,
        out string successorIssuerDid)
    {
        successorIssuerDid = string.Empty;
        throw new NotSupportedException();
    }
}
