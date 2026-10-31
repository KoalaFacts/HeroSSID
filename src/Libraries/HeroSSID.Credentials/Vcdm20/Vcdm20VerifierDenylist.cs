using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>The outcome of independently owned VC2 issuer and emergency denial policy.</summary>
public enum Vcdm20VerifierPolicyResult
{
    Invalid,
    DeniedByVerifier,
    IssuerReportedRevoked,
    SignedButStatusUnchecked,
    SignedNotListed
}

/// <summary>
/// Independent relying-party verification and exact-original-JWT emergency denial.
/// The implementation is intentionally absent in the initial runtime-red test commit.
/// </summary>
public static class Vcdm20VerifierDenylist
{
    public static Vcdm20VerifierPolicyResult Check(
        string credentialJwt, IReadOnlyCollection<string> trustedIssuerDids,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("VC2 verifier-owned emergency denial not implemented.");
    }

    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("VC2 verifier-owned emergency denial not implemented.");
    }
}
