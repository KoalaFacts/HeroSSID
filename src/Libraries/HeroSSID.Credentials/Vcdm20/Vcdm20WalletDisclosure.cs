using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Authenticated, full-disclosure preview for the opt-in direct VC2 holder flow.
/// This does not attest to real consent, revocation, identity or authorization.
/// </summary>
public sealed record Vcdm20WalletDisclosurePreview(
    string VerifierDid,
    string VerifierAudience,
    string TrustedIssuerDid,
    string HolderDid,
    string CredentialType,
    Uri SubjectContextUri,
    DateTimeOffset RequestExpiresAt,
    JsonElement VerifiedSubject,
    string RequestSha256,
    string CredentialSha256);

/// <summary>Wallet-side no-key preview and preview-bound VC2 presentation signing.</summary>
public static class Vcdm20WalletDisclosure
{
    /// <summary>
    /// Verify the independently pinned verifier request and original issuer
    /// credential without accessing a holder seed or consuming a challenge.
    /// </summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, TimeProvider clock,
        out Vcdm20WalletDisclosurePreview? preview)
    {
        preview = null;
        return false;
    }

    /// <summary>
    /// Only after wallet-owned full-disclosure consent, revalidate and sign the
    /// exact authentic request and original issuer credential shown at preview.
    /// </summary>
    public static string CreateHolderPresentationAfterPreview(
        Vcdm20WalletDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Test-only stub: VC2 wallet preflight is not implemented.");
}
