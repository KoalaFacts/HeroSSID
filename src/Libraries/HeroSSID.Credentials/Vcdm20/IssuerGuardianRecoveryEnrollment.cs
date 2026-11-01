using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Independently pre-pinned old-issuer-signed guardian enrollment evidence.
/// A valid signed artifact does not authorize key rotation or trust promotion.
/// </summary>
public static class IssuerGuardianRecoveryEnrollment
{
    public static string Create(string previousIssuerDid, byte[] previousIssuerSeed,
        IReadOnlyCollection<string> guardianDids, int requiredGuardianSignatures,
        Uri verifierAudience, DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        throw new NotSupportedException("Pre-enrolled recovery policy issuance is not implemented.");

    public static string Fingerprint(string signedEnrollmentJwt) =>
        throw new NotSupportedException("Pre-enrolled recovery policy fingerprint is not implemented.");

    public static bool TryVerify(string signedEnrollmentJwt, string trustedPreviousIssuerDid,
        string independentlyPinnedSha256, Uri verifierAudience, DateTimeOffset now,
        out string[] guardianDids, out int requiredGuardianSignatures) =>
        throw new NotSupportedException("Pre-enrolled recovery policy verification is not implemented.");

    public static PresentationChallenge IssueChallenge(IPresentationChallengeStore store,
        Guid verifierTenantId, string signedEnrollmentJwt, string independentlyPinnedSha256,
        string trustedPreviousIssuerDid, Uri verifierAudience, TimeProvider clock,
        TimeSpan? lifetime = null) =>
        throw new NotSupportedException("Pre-enrolled recovery challenge is not implemented.");

    public static bool TryVerifyAndConsume(IPresentationChallengeStore store,
        Guid verifierTenantId, string evidenceJson, string signedEnrollmentJwt,
        string independentlyPinnedSha256, string trustedPreviousIssuerDid,
        Uri verifierAudience, string expectedNonce, TimeProvider clock,
        out string successorIssuerDid) =>
        throw new NotSupportedException("Pre-enrolled recovery consumption is not implemented.");
}
