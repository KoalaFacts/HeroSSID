using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Authenticated full-disclosure preview for a wallet application. The digest
/// identifies the exact signed request and original issuer credential to show
/// before later holder signing; it is not evidence of human consent.
/// </summary>
public sealed record JwtVcJsonWalletDisclosurePreview(
    string VerifierDid,
    Uri ResponseUri,
    string TrustedIssuerDid,
    string HolderDid,
    string CredentialType,
    Uri SubjectContextUri,
    DateTimeOffset RequestExpiresAt,
    JsonElement VerifiedSubject,
    string RequestSha256,
    string CredentialSha256);


/// <summary>
/// Full-disclosure preview additionally bound to the exact issuer-signed,
/// short-lived VC1.1 status snapshot. Absence from an issuer-reported set
/// does not prove live non-revocation or completeness.
/// </summary>
public sealed record JwtVcJsonWalletStatusDisclosurePreview(
    JwtVcJsonWalletDisclosurePreview Disclosure,
    string SnapshotSha256);

/// <summary>
/// Wallet preflight for the bounded OpenID4VP jwt_vc_json direct_post profile.
/// This API never signs or consumes a challenge, nor does it obtain consent.
/// </summary>
public static class OpenId4VpJwtVcJsonWalletDisclosure
{
    /// <summary>
    /// Independently verify a pinned request and the original issuer JWT, and
    /// expose the entire signed subject to a wallet UI before asking permission.
    /// No holder private key is required for preview. The wallet must supply its
    /// own independently chosen verifier DID/callback and issuer trust policy.
    /// An authentic preview is not proof of current revocation status, holder
    /// control, actual user consent, identity or business authorization.
    /// </summary>
    public static bool TryPrepare(
        string requestJwt, string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string expectedIssuerDid, string credentialJwt, string holderDid,
        TimeProvider clock, out JwtVcJsonWalletDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        if (string.IsNullOrWhiteSpace(requestJwt) ||
            string.IsNullOrWhiteSpace(credentialJwt) ||
            string.IsNullOrWhiteSpace(expectedIssuerDid) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            !OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
                requestJwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri, clock, out var request) ||
            request is null ||
            !string.Equals(request.Challenge.TrustedIssuerDid,
                expectedIssuerDid, StringComparison.Ordinal) ||
            !JwtVcJsonCredential.TryVerify(credentialJwt, expectedIssuerDid,
                holderDid, expectedCredentialType, expectedSubjectContextUri,
                clock.GetUtcNow(), out JsonElement signedSubject))
        {
            return false;
        }

        preview = new JwtVcJsonWalletDisclosurePreview(
            expectedVerifierDid,
            expectedResponseUri,
            expectedIssuerDid,
            holderDid,
            expectedCredentialType,
            expectedSubjectContextUri,
            request.Challenge.ExpiresAt,
            signedSubject,
            Sha256(requestJwt),
            Sha256(credentialJwt));
        return true;
    }

    /// <summary>
    /// After the integrating application has obtained actual informed consent,
    /// independently reverify both original signed artifacts and require their
    /// exact digests and displayed subject to match the preview before signing.
    /// This prevents accidental post-preview swaps; it does not prove a human
    /// saw or approved the disclosure. The original signing API is still usable,
    /// and a wallet must enforce its own real consent interaction.
    /// </summary>
    public static string CreateHolderResponseFormAfterPreview(
        JwtVcJsonWalletDisclosurePreview preview,
        string requestJwt, string credentialJwt, byte[] holderSeed,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.VerifiedSubject.ValueKind != JsonValueKind.Object ||
            !TryPrepare(requestJwt, preview.VerifierDid, preview.ResponseUri,
                preview.CredentialType, preview.SubjectContextUri,
                preview.TrustedIssuerDid, credentialJwt, preview.HolderDid,
                clock, out var newlyVerified) ||
            newlyVerified is null ||
            preview.RequestExpiresAt != newlyVerified.RequestExpiresAt ||
            !string.Equals(preview.RequestSha256,
                newlyVerified.RequestSha256, StringComparison.Ordinal) ||
            !string.Equals(preview.CredentialSha256,
                newlyVerified.CredentialSha256, StringComparison.Ordinal) ||
            !string.Equals(preview.VerifiedSubject.GetRawText(),
                newlyVerified.VerifiedSubject.GetRawText(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Only the live verifier request and authentic issuer credential shown in the preview may be signed.",
                nameof(preview));
        }

        // The original VP creator rechecks the verifier signature, issuer JWT,
        // holder private key and expiry. Never sign by trusting preview metadata.
        return OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            requestJwt, preview.VerifierDid, preview.ResponseUri,
            preview.CredentialType, preview.SubjectContextUri,
            credentialJwt, preview.HolderDid, holderSeed, clock);
    }


    /// <summary>
    /// Prepare a status-gated full-disclosure preview. A missing, forged,
    /// revoked or stale issuer-signed status must not release subject claims.
    /// The issuer alone is responsible for its export's completeness.
    /// </summary>
    public static bool TryPrepareWithStatus(
        string requestJwt, string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string expectedIssuerDid, string credentialJwt, string holderDid,
        string issuerSignedSnapshotJwt, TimeProvider clock,
        out JwtVcJsonWalletStatusDisclosurePreview? preview)
    {
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        if (string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            issuerSignedSnapshotJwt.Length > 65_536 ||
            !TryPrepare(requestJwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri, expectedIssuerDid,
                credentialJwt, holderDid, clock, out var disclosure) ||
            disclosure is null ||
            JwtVcJsonRevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            // A valid issuer statement is not sufficient to disclose the subject
            // when this Wallet operation explicitly requires a signed status set.
            return false;
        }

        preview = new JwtVcJsonWalletStatusDisclosurePreview(
            disclosure, Sha256(issuerSignedSnapshotJwt));
        return true;
    }

    /// <summary>
    /// Require unchanged live signed status and the exact approved preview
    /// before the caller-owned holder key can sign a direct_post response.
    /// Does not attest to actual user consent or live non-revocation.
    /// </summary>
    public static string CreateHolderResponseFormAfterStatusPreview(
        JwtVcJsonWalletStatusDisclosurePreview preview, string requestJwt,
        string credentialJwt, string issuerSignedSnapshotJwt,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.Disclosure is null ||
            string.IsNullOrWhiteSpace(issuerSignedSnapshotJwt) ||
            issuerSignedSnapshotJwt.Length > 65_536 ||
            !string.Equals(preview.SnapshotSha256,
                Sha256(issuerSignedSnapshotJwt), StringComparison.Ordinal) ||
            JwtVcJsonRevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                preview.Disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            throw new ArgumentException(
                "A fresh, unchanged issuer-signed status snapshot for the previewed VC1.1 credential is required.",
                nameof(preview));
        }

        // Re-check the signed verifier request, issuer JWT, original digests,
        // full displayed claims and real holder seed before producing any proof.
        string form = CreateHolderResponseFormAfterPreview(
            preview.Disclosure, requestJwt, credentialJwt, holderSeed, clock);

        // Signing may cross the private 60-second status expiry boundary. Never
        // return a proof described as status-gated after the snapshot expires.
        if (JwtVcJsonRevocationSnapshot.Check(issuerSignedSnapshotJwt, credentialJwt,
                preview.Disclosure.TrustedIssuerDid, clock.GetUtcNow()) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            throw new ArgumentException(
                "The issuer-signed VC1.1 snapshot expired while signing.",
                nameof(issuerSignedSnapshotJwt));
        }

        return form;
    }

    private static string Sha256(string signedJwt) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signedJwt)));
}
