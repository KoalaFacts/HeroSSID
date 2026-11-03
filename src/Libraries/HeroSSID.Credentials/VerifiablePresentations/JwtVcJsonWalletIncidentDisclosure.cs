using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Full-disclosure VC1.1 Wallet preview bound to an independently maintained
/// earliest permitted issuer-signed status observation after an incident.
/// A signature and absence from an issuer-reported list are not live revocation.
/// </summary>
public sealed record JwtVcJsonWalletIncidentDisclosurePreview(
    JwtVcJsonWalletStatusDisclosurePreview Status,
    DateTimeOffset MinimumObservedAt);

/// <summary>
/// Opt-in incident-aware Wallet preflight for the bounded VC1.1 jwt_vc_json
/// OpenID4VP direct_post subset. The Wallet never reissues issuer statements.
/// The integrating Wallet alone obtains full-disclosure informed consent.
/// </summary>
public static class JwtVcJsonWalletIncidentDisclosure
{
    private const int MaximumStatusLength = 65_536;

    /// <summary>
    /// Authenticate the pinned verifier request, original issuer JWT and
    /// post-incident same-issuer signed status BEFORE exposing subject claims
    /// or receiving a holder key. Cutoff is independently maintained Wallet
    /// policy, never taken from request, credential or status evidence.
    /// </summary>
    public static bool TryPrepare(
        string requestJwt, string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string expectedIssuerDid, string credentialJwt, string holderDid,
        string issuerSignedSnapshotJwt, DateTimeOffset minimumObservedAt,
        TimeProvider clock, out JwtVcJsonWalletIncidentDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        DateTimeOffset now = clock.GetUtcNow();
        if (minimumObservedAt < DateTimeOffset.UnixEpoch ||
            minimumObservedAt > now ||
            string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            issuerSignedSnapshotJwt.Length > MaximumStatusLength ||
            JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt, expectedIssuerDid,
                now, minimumObservedAt) != RevocationSnapshotCheckResult.NotListed ||
            !OpenId4VpJwtVcJsonWalletDisclosure.TryPrepareWithStatus(
                requestJwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri,
                expectedIssuerDid, credentialJwt, holderDid,
                issuerSignedSnapshotJwt, clock, out var statusPreview) ||
            statusPreview is null ||
            // Preview can outlive a 60-second observation during slow verification.
            JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt, expectedIssuerDid,
                clock.GetUtcNow(), minimumObservedAt) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            return false;
        }

        preview = new JwtVcJsonWalletIncidentDisclosurePreview(
            statusPreview, minimumObservedAt);
        return true;
    }

    /// <summary>
    /// Following actual Wallet-owned consent, compare the current independent
    /// incident cutoff with the earlier preview, revalidate the exact signed
    /// request/issuer/status and displayed claims, then create the stronger
    /// holder-signed original-request SHA-256-bound response. A changed incident
    /// cutoff requires a new preflight and new consent.
    /// </summary>
    public static string CreateHolderBoundResponseFormAfterPreview(
        JwtVcJsonWalletIncidentDisclosurePreview preview, string requestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        DateTimeOffset minimumObservedAt, byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        JwtVcJsonWalletDisclosurePreview? original = preview.Status?.Disclosure;
        if (original is null || original.VerifiedSubject.ValueKind != JsonValueKind.Object ||
            preview.MinimumObservedAt != minimumObservedAt ||
            minimumObservedAt < DateTimeOffset.UnixEpoch ||
            minimumObservedAt > clock.GetUtcNow() ||
            !TryPrepare(requestJwt, original.VerifierDid, original.ResponseUri,
                original.CredentialType, original.SubjectContextUri,
                original.TrustedIssuerDid, credentialJwt, original.HolderDid,
                issuerSignedSnapshotJwt, minimumObservedAt, clock,
                out var rechecked) ||
            rechecked?.Status?.Disclosure is not JwtVcJsonWalletDisclosurePreview latest ||
            !string.Equals(preview.Status.SnapshotSha256,
                rechecked.Status.SnapshotSha256, StringComparison.Ordinal) ||
            !string.Equals(original.RequestSha256,
                latest.RequestSha256, StringComparison.Ordinal) ||
            !string.Equals(original.CredentialSha256,
                latest.CredentialSha256, StringComparison.Ordinal) ||
            original.RequestExpiresAt != latest.RequestExpiresAt ||
            !string.Equals(original.VerifiedSubject.GetRawText(),
                latest.VerifiedSubject.GetRawText(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "An unchanged Wallet preview and valid post-incident signed issuer status are required.",
                nameof(preview));
        }

        // Genuine holder Ed25519 signs the exact original verifier-signed JWT's
        // digest. This private binding is not third-party Wallet conformance.
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            requestJwt, original.VerifierDid, original.ResponseUri,
            original.CredentialType, original.SubjectContextUri,
            credentialJwt, original.HolderDid, holderSeed, clock);

        // Signing may cross the issuer's private 60-second observation expiry.
        // Never hand a previously status-gated proof to the caller after expiry.
        if (JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                issuerSignedSnapshotJwt, credentialJwt,
                original.TrustedIssuerDid, clock.GetUtcNow(),
                minimumObservedAt) != RevocationSnapshotCheckResult.NotListed)
        {
            throw new ArgumentException(
                "The authenticated post-incident issuer observation expired during holder signing.",
                nameof(issuerSignedSnapshotJwt));
        }

        return form;
    }
}
