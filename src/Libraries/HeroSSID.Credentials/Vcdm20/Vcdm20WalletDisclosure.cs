using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

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

/// <summary>
/// Wallet-side no-key preview and preview-bound VC2 presentation signing.
/// A wallet must obtain meaningful full-disclosure consent in its own UI.
/// </summary>
public static class Vcdm20WalletDisclosure
{
    /// <summary>
    /// Authenticate a verifier-signed, one-use request and the unchanged original
    /// issuer-signed direct VC2 JWT before giving claims to a wallet UI. The DID,
    /// audience, issuer, holder and vocabulary policies are independently pinned.
    /// This needs no private seed and cannot spend the verifier's challenge.
    /// </summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, TimeProvider clock,
        out Vcdm20WalletDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        if (string.IsNullOrWhiteSpace(signedRequestJwt) ||
            string.IsNullOrWhiteSpace(expectedVerifierDid) ||
            string.IsNullOrWhiteSpace(expectedAudience) ||
            string.IsNullOrWhiteSpace(expectedIssuerDid) ||
            string.IsNullOrWhiteSpace(expectedCredentialType) ||
            string.IsNullOrWhiteSpace(credentialJwt) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            !OfflineSignedPresentationRequest.TryRead(signedRequestJwt,
                expectedVerifierDid, expectedAudience, clock, out var challenge) ||
            challenge is null ||
            !string.Equals(challenge.TrustedIssuerDid, expectedIssuerDid,
                StringComparison.Ordinal) ||
            !Vcdm20JoseCredential.TryVerify(credentialJwt, expectedIssuerDid,
                holderDid, expectedCredentialType, expectedContextUri,
                clock.GetUtcNow(), out JsonElement signedSubject))
        {
            return false;
        }

        preview = new Vcdm20WalletDisclosurePreview(
            expectedVerifierDid,
            expectedAudience,
            expectedIssuerDid,
            holderDid,
            expectedCredentialType,
            expectedContextUri,
            challenge.ExpiresAt,
            signedSubject,
            Sha256(signedRequestJwt),
            Sha256(credentialJwt));
        return true;
    }

    /// <summary>
    /// After the integrating Wallet has obtained actual informed consent, recheck
    /// both signed artifacts, their exact compact-JWS digests, expiry and disclosed
    /// subject before invoking the independent Ed25519 holder signer. This guards
    /// against request/credential swaps between preview and signing; it cannot
    /// prove the holder actually saw or approved the preview. The wallet owns and
    /// must clear its seed. A verifier must still check status and business policy.
    /// </summary>
    public static string CreateHolderPresentationAfterPreview(
        Vcdm20WalletDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.VerifiedSubject.ValueKind != JsonValueKind.Object ||
            !TryPrepare(signedRequestJwt, preview.VerifierDid,
                preview.VerifierAudience, preview.CredentialType,
                preview.SubjectContextUri, preview.TrustedIssuerDid,
                credentialJwt, preview.HolderDid, clock, out var reverified) ||
            reverified is null ||
            preview.RequestExpiresAt != reverified.RequestExpiresAt ||
            !string.Equals(preview.RequestSha256,
                reverified.RequestSha256, StringComparison.Ordinal) ||
            !string.Equals(preview.CredentialSha256,
                reverified.CredentialSha256, StringComparison.Ordinal) ||
            !string.Equals(preview.VerifiedSubject.GetRawText(),
                reverified.VerifiedSubject.GetRawText(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Only the live verifier request and authentic direct VC2 credential shown in the preview may be signed.",
                nameof(preview));
        }

        // Revalidate issuer provenance, exact verifier request and actual holder
        // seed again inside the existing VP signer; preview metadata is never a
        // substitute for cryptographic checks and verifier one-use enforcement.
        return Vcdm20JosePresentation.Create(
            signedRequestJwt, preview.VerifierDid, preview.VerifierAudience,
            credentialJwt, preview.CredentialType, preview.SubjectContextUri,
            preview.HolderDid, holderSeed, clock);
    }

    private static string Sha256(string jwt) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));
}
