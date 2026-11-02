using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// A Wallet-only status preview with a separately trusted incident observation cutoff.
/// The issuer's signed absence is not live revocation, identity or authority.
/// </summary>
public sealed record Vcdm20WalletIncidentDisclosurePreview(
    Vcdm20WalletStatusDisclosurePreview Status,
    DateTimeOffset MinimumObservedAt);

/// <summary>
/// Opt-in incident-aware full-disclosure Wallet flow. No holder key is accessed
/// during preview, and signing cannot establish real human consent.
/// </summary>
public static class Vcdm20WalletIncidentDisclosure
{
    /// <summary>Authenticate current, post-incident status and exact signed Wallet disclosure policy.</summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, TimeProvider clock,
        out Vcdm20WalletIncidentDisclosurePreview? preview)
    {
        preview = null;
        throw new NotSupportedException("Incident observation policy is not implemented.");
    }

    /// <summary>Recheck independent incident policy after Wallet consent and before signing.</summary>
    public static string CreateHolderBoundPresentationAfterPreview(
        Vcdm20WalletIncidentDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Incident observation policy is not implemented.");
}
