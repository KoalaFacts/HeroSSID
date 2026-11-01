using System;
using System.Collections.Generic;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>Independent-signer recovery: no coordinator needs guardian private keys.</summary>
public static class IssuerGuardianRecoveryDistributed
{
    public static string CreateSuccessorSignature(string previousIssuerDid,
        string successorIssuerDid, byte[] successorSeed, Uri verifierAudience,
        string nonce, TimeProvider clock) =>
        throw new NotSupportedException("Distributed recovery signing is not implemented.");

    public static bool TryCreateGuardianApproval(string successorSignature,
        string expectedPreviousIssuerDid, string expectedSuccessorIssuerDid,
        string guardianDid, byte[] guardianSeed, Uri expectedVerifierAudience,
        string expectedNonce, DateTimeOffset now, out string approval)
    {
        approval = string.Empty;
        throw new NotSupportedException("Independent guardian approval is not implemented.");
    }

    public static string AssembleEvidence(string successorSignature,
        IReadOnlyCollection<string> guardianApprovals) =>
        throw new NotSupportedException("Distributed recovery assembly is not implemented.");
}
