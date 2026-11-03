namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Full-disclosure VC1.1 Wallet preview bound to an independently controlled
/// post-incident issuer-status observation cutoff. Not a consent attestation.
/// </summary>
public sealed record JwtVcJsonWalletIncidentDisclosurePreview(
    JwtVcJsonWalletStatusDisclosurePreview Status,
    DateTimeOffset MinimumObservedAt);

/// <summary>
/// Opt-in incident-aware Wallet entrypoints. The original issuer statement is
/// only held and presented, never reissued by the Wallet.
/// </summary>
public static class JwtVcJsonWalletIncidentDisclosure
{
    /// <summary>
    /// Verify an actual post-incident signed issuer observation before
    /// allowing the Wallet to show any full-disclosure subject claim.
    /// </summary>
    public static bool TryPrepare(
        string requestJwt, string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string expectedIssuerDid, string credentialJwt, string holderDid,
        string issuerSignedSnapshotJwt, DateTimeOffset minimumObservedAt,
        TimeProvider clock, out JwtVcJsonWalletIncidentDisclosurePreview? preview)
    {
        preview = null;
        return false;
    }

    /// <summary>
    /// Require a fresh approved preview and the current independently selected
    /// cutoff before creating a holder-signed, request-bound direct_post body.
    /// </summary>
    public static string CreateHolderBoundResponseFormAfterPreview(
        JwtVcJsonWalletIncidentDisclosurePreview preview, string requestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Red-phase test-only placeholder.");
}
