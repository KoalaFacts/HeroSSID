namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in pre-enrolled guardian signatures as evidence for a lost issuer-key recovery.
/// Verification never changes DID trust, authorizes an action or consumes a challenge.
/// </summary>
public static class IssuerGuardianRecovery
{
    public static string Create(string previousIssuerDid, string successorIssuerDid,
        byte[] successorSeed, IReadOnlyDictionary<string, byte[]> guardianSeeds,
        Uri verifierAudience, string nonce, TimeProvider clock) =>
        throw new NotSupportedException("Guardian recovery proof issuance is not implemented.");

    public static bool TryVerify(string proofJson, string trustedPreviousIssuerDid,
        IReadOnlyCollection<string> trustedGuardianDids, int requiredGuardianSignatures,
        Uri expectedVerifierAudience, string expectedNonce, DateTimeOffset now,
        out string successorIssuerDid) =>
        throw new NotSupportedException("Guardian recovery proof verification is not implemented.");
}
