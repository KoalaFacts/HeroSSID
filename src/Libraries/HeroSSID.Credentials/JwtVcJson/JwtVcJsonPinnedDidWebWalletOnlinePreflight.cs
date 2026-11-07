using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// A Wallet display preview and the exact signed issuer observation used to prepare it.
/// The Wallet still owns the real full-disclosure UI and informed-consent decision.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebOnlineWalletPreview(
    JwtVcJsonPinnedDidWebWalletEmergencyPreview Disclosure, string SignedStatusJwt);

/// <summary>
/// Opt-in online Wallet preview of a pinned did:web issuer's original VC1.1 JWT.
/// This does not imply live non-revocation, independent Wallet interoperability,
/// consent, real-world identity or business authorization.
/// </summary>
public static class JwtVcJsonPinnedDidWebWalletOnlinePreflight
{
    /// <summary>
    /// Verify the complete independently approved credential and request BEFORE
    /// an isolated status GET, then verify the signed exact-original status and
    /// Wallet emergency policy BEFORE returning any full-disclosure claims.
    /// A caller-supplied HttpClient must be independently audited and credential-free.
    /// No holder private key, nonce consumption or consent action occurs here.
    /// </summary>
    public static Task<JwtVcJsonPinnedDidWebOnlineWalletPreview?> TryPrepareAsync(
        Uri independentlyPinnedStatusUri, HttpClient http,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid,
        IReadOnlyCollection<string> deniedCredentialSha256, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        Task.FromException<JwtVcJsonPinnedDidWebOnlineWalletPreview?>(
            new NotSupportedException("Runtime RED: online Wallet preflight is not yet implemented."));

    /// <summary>
    /// Creates a holder-signed proof only after the integrating Wallet has
    /// displayed all verified claims and actually obtained informed consent.
    /// </summary>
    public static string CreateAfterPreview(
        JwtVcJsonPinnedDidWebOnlineWalletPreview preview,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        byte[] independentlyPinnedIssuerPublicKey,
        IReadOnlyCollection<string> deniedCredentialSha256,
        byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Runtime RED: online Wallet consent path is not yet implemented.");
}
