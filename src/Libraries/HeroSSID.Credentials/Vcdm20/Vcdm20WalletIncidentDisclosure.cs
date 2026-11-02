namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// A Wallet-only full-disclosure status preview bound to the exact issuer-signed
/// status and an independently maintained minimum issuer observation time.
/// Neither the preview nor the issuer's signed absence is a live revocation proof.
/// </summary>
public sealed record Vcdm20WalletIncidentDisclosurePreview(
    Vcdm20WalletStatusDisclosurePreview Status,
    DateTimeOffset MinimumObservedAt);

/// <summary>
/// Opt-in incident-aware full-disclosure Wallet flow. The Wallet only holds
/// issuer statements and creates holder-signed presentations after its own
/// consent UI. This private status format cannot attest real-world identity
/// or business authorization.
/// </summary>
public static class Vcdm20WalletIncidentDisclosure
{
    private const int MaximumStatusLength = 65_536;

    /// <summary>
    /// Before exposing any subject claim or using the holder key, require an
    /// independently pinned verifier-signed credential type/context and a real
    /// issuer-signed status observation no earlier than the Wallet operator's
    /// own incident cutoff. The issuer's omitted digest is not proof of
    /// complete or real-time non-revocation.
    /// </summary>
    public static bool TryPrepare(
        string signedRequestJwt, string expectedVerifierDid, string expectedAudience,
        string expectedCredentialType, Uri expectedContextUri, string expectedIssuerDid,
        string credentialJwt, string holderDid, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, TimeProvider clock,
        out Vcdm20WalletIncidentDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        DateTimeOffset now = clock.GetUtcNow();
        if (minimumObservedAt < DateTimeOffset.UnixEpoch ||
            minimumObservedAt > now ||
            string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            issuerSignedSnapshotJwt.Length > MaximumStatusLength ||
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt, expectedIssuerDid,
                now, minimumObservedAt) != Vcdm20RevocationCheckResult.SignedNotListed ||
            !Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
                signedRequestJwt, expectedVerifierDid, expectedAudience,
                expectedCredentialType, expectedContextUri, expectedIssuerDid,
                credentialJwt, holderDid, issuerSignedSnapshotJwt, clock,
                out var statusPreview) ||
            statusPreview is null ||
            // A signing operation or slow status reader may cross expiration.
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt, expectedIssuerDid,
                clock.GetUtcNow(), minimumObservedAt) !=
                Vcdm20RevocationCheckResult.SignedNotListed)
        {
            return false;
        }

        preview = new Vcdm20WalletIncidentDisclosurePreview(
            statusPreview, minimumObservedAt);
        return true;
    }

    /// <summary>
    /// Reauthenticate the *unchanged* request, credential, status, displayed
    /// claims and independently supplied incident cutoff after actual Wallet
    /// consent. An incident during the consent interval requires a new preview.
    /// The holder signs the exact original verifier request SHA-256 and the
    /// verifier still owns the independent pin and atomic challenge store.
    /// </summary>
    public static string CreateHolderBoundPresentationAfterPreview(
        Vcdm20WalletIncidentDisclosurePreview preview, string signedRequestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        if (preview.Status?.Disclosure is null ||
            preview.MinimumObservedAt != minimumObservedAt ||
            minimumObservedAt < DateTimeOffset.UnixEpoch ||
            minimumObservedAt > now ||
            string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            issuerSignedSnapshotJwt.Length > MaximumStatusLength ||
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt,
                preview.Status.Disclosure.TrustedIssuerDid, now,
                minimumObservedAt) != Vcdm20RevocationCheckResult.SignedNotListed)
        {
            throw new ArgumentException(
                "An unchanged authenticated Wallet preview and post-incident issuer status are required.",
                nameof(preview));
        }

        // The strict existing signer checks original verifier and issuer
        // signatures, all preview fields, exact request/credential/status
        // digests, signed type/context and holder key BEFORE signing.
        string proof =
            Vcdm20WalletDisclosure.CreateHolderBoundPresentationAfterStatusPreviewRequiringSignedPolicy(
                preview.Status, signedRequestJwt, credentialJwt,
                issuerSignedSnapshotJwt, holderSeed, clock);

        // Private-key signing can cross the 60-second status expiry.
        // Never release a proof that the Wallet treated as incident-checked
        // after the authentic issuer observation has become stale.
        if (Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt,
                preview.Status.Disclosure.TrustedIssuerDid, clock.GetUtcNow(),
                minimumObservedAt) != Vcdm20RevocationCheckResult.SignedNotListed)
        {
            throw new ArgumentException(
                "The authenticated post-incident issuer status expired during holder signing.",
                nameof(issuerSignedSnapshotJwt));
        }

        return proof;
    }
}
