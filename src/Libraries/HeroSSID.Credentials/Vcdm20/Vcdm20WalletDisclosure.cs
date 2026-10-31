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
/// Full-disclosure preview bound to the exact issuer-signed, short-lived VC2
/// revocation snapshot. SignedNotListed is not proof of live non-revocation.
/// </summary>
public sealed record Vcdm20WalletStatusDisclosurePreview(
    Vcdm20WalletDisclosurePreview Disclosure,
    string SnapshotSha256);

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
            (!OfflineSignedPresentationRequest.TryRead(signedRequestJwt,
                expectedVerifierDid, expectedAudience, clock, out var challenge) &&
             !OfflineSignedPresentationRequest.TryReadPolicyBound(signedRequestJwt,
                expectedVerifierDid, expectedAudience, expectedCredentialType,
                expectedContextUri, clock, out challenge)) ||
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
    /// Reject legacy signed requests that do not bind a verifier-selected credential
    /// type and HTTPS subject context. The Wallet must independently pin this policy
    /// to avoid accepting an authentic but downgraded unbound verifier request.
    /// </summary>
    public static bool TryPrepareRequiringSignedPolicy(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, TimeProvider clock,
        out Vcdm20WalletDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;
        return OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, clock, out _) &&
            TryPrepare(signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, expectedIssuerDid,
                credentialJwt, holderDid, clock, out preview);
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

    /// <summary>
    /// Strict status-aware Wallet preflight requiring an issuer status snapshot AND
    /// a verifier-signed credential type and exact HTTPS context. The legacy
    /// status-aware entry point remains available for existing integrations.
    /// </summary>
    public static bool TryPrepareWithStatusRequiringSignedPolicy(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, string issuerSignedSnapshotJwt,
        TimeProvider clock, out Vcdm20WalletStatusDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        // Enforce the verifier's independently pinned type and vocabulary BEFORE
        // the status-aware path can expose any issuer-authenticated subject claims.
        // The compatible status-aware entry point intentionally also accepts legacy
        // requests; the strict API must not silently downgrade to those requests.
        return OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, clock, out _) &&
            TryPrepareWithStatus(
                signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, expectedIssuerDid,
                credentialJwt, holderDid, issuerSignedSnapshotJwt, clock,
                out preview);
    }

    /// <summary>
    /// Verify an independently pinned issuer and verifier, full-disclosure VC2
    /// claims and an authentic, current same-issuer revocation snapshot without
    /// a holder private key. Only an authentic SignedNotListed set can preview.
    /// </summary>
    public static bool TryPrepareWithStatus(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, string issuerSignedSnapshotJwt,
        TimeProvider clock, out Vcdm20WalletStatusDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        if (string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            !TryPrepare(signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, expectedIssuerDid,
                credentialJwt, holderDid, clock, out var disclosure) ||
            disclosure is null ||
            Vcdm20RevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            // Never return even an authentic subject to the Wallet UI when
            // the independently pinned issuer status is missing or negative.
            return false;
        }

        preview = new Vcdm20WalletStatusDisclosurePreview(
            disclosure, Sha256(issuerSignedSnapshotJwt));
        return true;
    }

    /// <summary>
    /// After informed consent, recheck both independent signed policies and the
    /// exact issuer status before signing with the holder's private seed.
    /// </summary>
    public static string CreateHolderPresentationAfterStatusPreviewRequiringSignedPolicy(
        Vcdm20WalletStatusDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        // A preview record is caller-controlled data. At signing time enforce the
        // policy-bound verifier signature again, even when the caller passes a
        // status preview produced by the permissive legacy-compatible API.
        if (preview.Disclosure is null ||
            preview.Disclosure.SubjectContextUri is null ||
            !OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, preview.Disclosure.VerifierDid,
                preview.Disclosure.VerifierAudience,
                preview.Disclosure.CredentialType,
                preview.Disclosure.SubjectContextUri, clock, out var challenge) ||
            challenge is null ||
            !string.Equals(challenge.TrustedIssuerDid,
                preview.Disclosure.TrustedIssuerDid, StringComparison.Ordinal) ||
            challenge.ExpiresAt != preview.Disclosure.RequestExpiresAt)
        {
            throw new ArgumentException(
                "A live verifier-signed credential type and HTTPS context policy is required.",
                nameof(preview));
        }

        // Revalidate the exact issuer-signed status, unchanged request/credential,
        // displayed subject, expiry and the real holder Ed25519 key in the
        // existing fail-closed signer after the stronger verifier-policy check.
        return CreateHolderPresentationAfterStatusPreview(
            preview, signedRequestJwt, credentialJwt, issuerSignedSnapshotJwt,
            holderSeed, clock);
    }

    /// <summary>
    /// Recheck the exact verified snapshot, request, credential and full disclosed
    /// subject at signing time before invoking the actual holder private key.
    /// </summary>
    public static string CreateHolderPresentationAfterStatusPreview(
        Vcdm20WalletStatusDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.Disclosure is null ||
            string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            !string.Equals(preview.SnapshotSha256, Sha256(issuerSignedSnapshotJwt),
                StringComparison.Ordinal) ||
            Vcdm20RevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                preview.Disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            throw new ArgumentException(
                "A current, unchanged issuer-signed status for the previewed VC2 credential is required.",
                nameof(preview));
        }

        // This existing signer independently reauthenticates the exact
        // verifier-signed request, issuer-signed VC2, displayed subject and
        // holder DID before it accesses the caller-owned private seed.
        string presentation = CreateHolderPresentationAfterPreview(
            preview.Disclosure, signedRequestJwt, credentialJwt, holderSeed, clock);

        // Signing may have crossed the snapshot expiry boundary. A proof
        // with expired status must never be returned as status-checked.
        if (Vcdm20RevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                preview.Disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            throw new ArgumentException(
                "The issuer-signed snapshot expired while creating the presentation.",
                nameof(issuerSignedSnapshotJwt));
        }

        return presentation;
    }

    private static string Sha256(string jwt) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));
}
