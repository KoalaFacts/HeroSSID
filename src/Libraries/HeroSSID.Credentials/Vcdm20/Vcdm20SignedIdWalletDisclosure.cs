using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

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
    /// Authenticate the policy-bound verifier request, original issuer signature,
    /// exact signed credential identifier and required subject values, then
    /// same-issuer status meeting a wallet-owned observation cutoff. Expose no
    /// subject and access no holder private key unless every check succeeds.
    /// </summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredClaims, string issuerSnapshotJwt,
        DateTimeOffset minimumObservedAtUtc, TimeProvider clock,
        out Vcdm20SignedIdWalletPreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(requiredClaims);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        if (string.IsNullOrWhiteSpace(signedRequestJwt) ||
            string.IsNullOrWhiteSpace(expectedVerifierDid) ||
            string.IsNullOrWhiteSpace(expectedAudience) ||
            string.IsNullOrWhiteSpace(expectedCredentialType) ||
            string.IsNullOrWhiteSpace(expectedIssuerDid) ||
            string.IsNullOrWhiteSpace(credentialJwt) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            string.IsNullOrWhiteSpace(issuerSnapshotJwt) ||
            // Unlike the legacy compatible request preview, this new workflow
            // requires the verifier itself to sign the exact type and context.
            !OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, clock,
                out PresentationChallenge? challenge) ||
            challenge is null ||
            !string.Equals(challenge.TrustedIssuerDid, expectedIssuerDid,
                StringComparison.Ordinal) ||
            !Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
                credentialJwt, [expectedIssuerDid], holderDid,
                expectedCredentialType, expectedContextUri, expectedCredentialId,
                requiredClaims, clock.GetUtcNow(), out string actualIssuer,
                out JsonElement subject) ||
            !string.Equals(actualIssuer, expectedIssuerDid,
                StringComparison.Ordinal) ||
            // Trust and observation cutoff come from the Wallet's own policy,
            // not the issuer's signed status or the verifier's request.
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSnapshotJwt, credentialJwt, actualIssuer,
                clock.GetUtcNow(), minimumObservedAtUtc) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            return false;
        }

        // An authentic issuer signature or snapshot is not enough if the
        // verifier request or issuer credential expired during the checks.
        // Re-evaluate every expiry-sensitive acceptance condition against one
        // final clock sample before disclosing any subject data. The status
        // checker alone authenticates the original signature, not validUntil.
        DateTimeOffset finalNow = clock.GetUtcNow();
        if (challenge.ExpiresAt <= finalNow ||
            !Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
                credentialJwt, [expectedIssuerDid], holderDid,
                expectedCredentialType, expectedContextUri, expectedCredentialId,
                requiredClaims, finalNow, out _, out _) ||
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSnapshotJwt, credentialJwt, actualIssuer,
                finalNow, minimumObservedAtUtc) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            return false;
        }

        // Do not retain the caller's mutable trust dictionary in the preview.
        // The preview remains application data, not a consent attestation.
        var fixedClaims = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(requiredClaims, StringComparer.Ordinal));
        preview = new Vcdm20SignedIdWalletPreview(
            expectedVerifierDid, expectedAudience, actualIssuer, holderDid,
            expectedCredentialType, expectedContextUri, expectedCredentialId,
            fixedClaims, minimumObservedAtUtc, challenge.ExpiresAt,
            subject, Digest(signedRequestJwt), Digest(credentialJwt),
            Digest(issuerSnapshotJwt));
        return true;
    }

    /// <summary>
    /// After the integrating wallet obtains actual full-disclosure informed
    /// consent, recheck the exact previewed signed request, issuer credential,
    /// status, subject, expiry, pinned policy and key before holder signing.
    /// The verifier independently consumes its one-use challenge.
    /// </summary>
    public static string CreateAfterPreview(
        Vcdm20SignedIdWalletPreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSnapshotJwt, byte[] holderSeed,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.VerifiedSubject.ValueKind != JsonValueKind.Object ||
            preview.RequiredClaims is null ||
            !TryPrepare(signedRequestJwt, preview.VerifierDid, preview.Audience,
                preview.CredentialType, preview.ContextUri, preview.IssuerDid,
                credentialJwt, preview.HolderDid, preview.CredentialId,
                preview.RequiredClaims, issuerSnapshotJwt,
                preview.MinimumObservedAtUtc, clock, out var reverified) ||
            reverified is null ||
            reverified.RequestExpiresAt != preview.RequestExpiresAt ||
            !string.Equals(reverified.RequestSha256, preview.RequestSha256,
                StringComparison.Ordinal) ||
            !string.Equals(reverified.CredentialSha256, preview.CredentialSha256,
                StringComparison.Ordinal) ||
            !string.Equals(reverified.SnapshotSha256, preview.SnapshotSha256,
                StringComparison.Ordinal) ||
            !string.Equals(reverified.VerifiedSubject.GetRawText(),
                preview.VerifiedSubject.GetRawText(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Only the exact live issuer, verifier and status artifacts disclosed in the approved preview may be signed.",
                nameof(preview));
        }

        // This existing signer independently checks the issuer's real
        // signature, exact signed ID, request and true holder Ed25519 seed.
        string vp = Vcdm20JosePresentation.CreateWithSignedCredentialId(
            signedRequestJwt, preview.VerifierDid, preview.Audience,
            credentialJwt, preview.CredentialType, preview.ContextUri,
            preview.CredentialId, preview.HolderDid, holderSeed, clock);

        // Signing may cross the credential's validUntil or the verifier
        // request/status expiry after the underlying holder signer rechecked
        // them. Use a final clock sample to gate all three originals together.
        // The snapshot authenticator does NOT validate credential lifetime.
        if (!OfflineSignedPresentationRequest.TryReadPolicyBound(
                signedRequestJwt, preview.VerifierDid, preview.Audience,
                preview.CredentialType, preview.ContextUri, clock,
                out PresentationChallenge? challenge) ||
            challenge is null || challenge.ExpiresAt != preview.RequestExpiresAt)
        {
            throw new ArgumentException(
                "The original verifier request expired during holder signing.",
                nameof(signedRequestJwt));
        }

        DateTimeOffset finalNow = clock.GetUtcNow();
        if (challenge.ExpiresAt <= finalNow ||
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSnapshotJwt, credentialJwt, preview.IssuerDid,
                finalNow, preview.MinimumObservedAtUtc) !=
                Vcdm20RevocationCheckResult.SignedNotListed ||
            !Vcdm20JoseCredential.TryVerifyWithId(
                credentialJwt, preview.IssuerDid, preview.HolderDid,
                preview.CredentialType, preview.ContextUri, finalNow,
                out _, out string? verifiedCredentialId) ||
            !string.Equals(verifiedCredentialId, preview.CredentialId.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The verifier request, issuer credential or exact status expired during holder signing.",
                nameof(issuerSnapshotJwt));
        }

        return vp;
    }

    private static string Digest(string artifact) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(artifact)));
}
