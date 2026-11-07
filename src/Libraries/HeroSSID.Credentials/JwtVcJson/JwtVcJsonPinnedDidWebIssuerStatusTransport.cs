using HeroSSID.Credentials.CredentialRevocation;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Wallet retrieval of an independently pinned issuer's exact VC1.1 status.
/// This is a private HeroSSID status format, not W3C Status List conformance.
/// </summary>
public sealed record JwtVcJsonIssuerStatusFetchResult(
    string SignedStatusJwt, RevocationSnapshotCheckResult Status);

/// <summary>
/// Fetches a genuine short-lived did:web issuer status from an operator-pinned
/// public HTTPS endpoint. This never promotes an issuer or grants authorization.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerStatusTransport
{
    public static Task<JwtVcJsonIssuerStatusFetchResult?> FetchVerifiedStatusAsync(
        Uri independentlyPinnedStatusUri, HttpClient http, string originalCredentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("RED helper: HTTPS signed-status retrieval is not implemented.");

    public static Task<JwtVcJsonIssuerStatusFetchResult?> FetchVerifiedStatusWithIsolatedTransportAsync(
        Uri independentlyPinnedStatusUri, string originalCredentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("RED helper: isolated signed-status transport is not implemented.");
}
