namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Two-key signed successor attestation. A did:key identifier never changes;
/// verifiers must decide locally whether to trust a separately named successor.
/// </summary>
public static class IssuerKeySuccessorAttestation
{
    /// <summary>Create a verifier-targeted statement signed by both issuer keys.</summary>
    public static string Create(
        string previousIssuerDid, string successorIssuerDid,
        byte[] previousIssuerSeed, byte[] successorIssuerSeed,
        Uri verifierAudience, string challengeNonce, TimeProvider clock)
    {
        throw new NotSupportedException("Successor attestation is not implemented.");
    }

    /// <summary>Verify both signatures and the pinned previous DID, audience and nonce.</summary>
    public static bool TryVerify(
        string attestationJson, string trustedPreviousIssuerDid,
        Uri expectedVerifierAudience, string expectedNonce,
        DateTimeOffset now, out string successorIssuerDid)
    {
        successorIssuerDid = string.Empty;
        return false;
    }
}
