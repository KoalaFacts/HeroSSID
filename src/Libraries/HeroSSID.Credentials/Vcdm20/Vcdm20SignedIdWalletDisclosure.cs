using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// A full-disclosure wallet preview of an exact signed-ID VC2 membership credential,
/// independently pinned issuer and required values, and genuine issuer status.
/// The wallet application must obtain actual consent; this is not a consent proof.
/// </summary>
public sealed record Vcdm20SignedIdWalletPreview(
    string VerifierDid,
    string Audience,
    string IssuerDid,
    string HolderDid,
    string CredentialType,
    Uri ContextUri,
    Uri CredentialId,
    IReadOnlyDictionary<string, string> RequiredClaims,
    DateTimeOffset MinimumObservedAtUtc,
    DateTimeOffset RequestExpiresAt,
    JsonElement VerifiedSubject,
    string RequestSha256,
    string CredentialSha256,
    string SnapshotSha256);

/// <summary>
/// Wallet-side consent boundary for a status-checked, exact-ID membership VP.
/// The independent verifier still owns issuer trust, nonce consumption and policy.
/// </summary>
public static class Vcdm20SignedIdWalletDisclosure
{
    /// <summary>
    /// Authenticate the verifier request, original issuer signature, exact signed
    /// credential identifier and required subject values, then genuine issuer status,
    /// before returning any subject claims or touching the holder private seed.
    /// </summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredClaims, string issuerSnapshotJwt,
        DateTimeOffset minimumObservedAtUtc, TimeProvider clock,
        out Vcdm20SignedIdWalletPreview? preview)
    {
        preview = null;
        throw new NotSupportedException("Runtime RED: signed-ID membership wallet preflight not implemented.");
    }

    /// <summary>
    /// After the integrating wallet obtains informed consent, reauthenticate
    /// and bind the exact previewed request, credential, status and subject
    /// to the holder's real Ed25519-signed full-disclosure presentation.
    /// </summary>
    public static string CreateAfterPreview(
        Vcdm20SignedIdWalletPreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSnapshotJwt, byte[] holderSeed,
        TimeProvider clock) =>
        throw new NotSupportedException("Runtime RED: consent-bound signed-ID holder proof not implemented.");
}
