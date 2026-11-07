using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Full-disclosure wallet preview of a verified did:web VC1.1 credential,
/// tied to its exact fresh issuer-signed status and verifier request.
/// This is application-visible data, not evidence of human consent.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebWalletPreview(
    PresentationChallenge Challenge, string TrustedIssuerDid,
    string TrustedVerificationMethodId, string ExpectedIssuerName,
    Uri ExpectedCredentialId, string ExpectedCredentialType,
    Uri ExpectedSubjectContextUri, string HolderDid,
    JsonElement VerifiedSubject, string CredentialSha256,
    string StatusSha256, string IssuerPublicKeySha256);

/// <summary>
/// Holder-side, SDK-only did:web VC1.1 full-disclosure preflight.
/// The integrating wallet must independently authenticate the verifier's
/// request and issuer trust pins, display every claim and obtain actual
/// informed consent. No signing, nonce consumption or wallet UI occurs here.
/// </summary>
public static class JwtVcJsonPinnedDidWebWalletPreflight
{
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumStatusLength = 8_192;

    /// <summary>
    /// Reveal claims to the wallet UI only when the original issuer JWT and
    /// same-issuer, exact-credential 60-second status are genuine, non-revoked
    /// and current. An issuer's signed observation is not proof of live status.
    /// No holder signing seed is accepted by this method.
    /// </summary>
    public static bool TryPrepare(
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid, TimeProvider clock,
        out JwtVcJsonPinnedDidWebWalletPreview? preview)
    {
        ArgumentNullException.ThrowIfNull(authenticatedChallenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(statusJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(clock);
        preview = null;

        DateTimeOffset now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumCredentialLength ||
            string.IsNullOrWhiteSpace(statusJwt) ||
            statusJwt.Length > MaximumStatusLength ||
            !ValidRequest(authenticatedChallenge, trustedIssuerDid,
                expectedCredentialType, expectedSubjectContextUri, now))
        {
            return false;
        }

        // The caller's separately enrolled key is a trust-policy INPUT.
        // Never infer its authority from an untrusted DID document or JWT.
        byte[] issuerPin = independentlyPinnedIssuerPublicKey.ToArray();
        if (!JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                credentialJwt, trustedIssuerDid, trustedVerificationMethodId,
                issuerPin, expectedIssuerName, expectedCredentialId, holderDid,
                expectedCredentialType, expectedSubjectContextUri,
                now, out JsonElement subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            JwtVcJsonPinnedDidWebIssuerStatus.CheckSignedStatus(
                statusJwt, credentialJwt, trustedIssuerDid,
                trustedVerificationMethodId, issuerPin, now) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            return false;
        }

        preview = new JwtVcJsonPinnedDidWebWalletPreview(
            authenticatedChallenge, trustedIssuerDid, trustedVerificationMethodId,
            expectedIssuerName, expectedCredentialId, expectedCredentialType,
            expectedSubjectContextUri, holderDid, subject,
            Digest(credentialJwt), Digest(statusJwt),
            Convert.ToHexStringLower(SHA256.HashData(issuerPin)));
        return true;
    }

    /// <summary>
    /// After the wallet application has actually obtained informed consent,
    /// verify the exact credential, status, pin, displayed claims and live
    /// authenticated challenge again, then sign the original issuer credential
    /// in a holder-controlled full-disclosure VP. Never trust preview metadata
    /// in place of original signed inputs. This cannot attest to consent itself.
    /// </summary>
    public static string CreateAfterPreview(
        JwtVcJsonPinnedDidWebWalletPreview preview,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, byte[] independentlyPinnedIssuerPublicKey,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(authenticatedChallenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(statusJwt);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (preview.VerifiedSubject.ValueKind != JsonValueKind.Object ||
            !Equals(preview.Challenge, authenticatedChallenge) ||
            !TryPrepare(authenticatedChallenge, credentialJwt, statusJwt,
                preview.TrustedIssuerDid, preview.TrustedVerificationMethodId,
                independentlyPinnedIssuerPublicKey, preview.ExpectedIssuerName,
                preview.ExpectedCredentialId, preview.ExpectedCredentialType,
                preview.ExpectedSubjectContextUri, preview.HolderDid,
                clock, out JwtVcJsonPinnedDidWebWalletPreview? current) ||
            current is null ||
            !string.Equals(preview.CredentialSha256, current.CredentialSha256,
                StringComparison.Ordinal) ||
            !string.Equals(preview.StatusSha256, current.StatusSha256,
                StringComparison.Ordinal) ||
            !string.Equals(preview.IssuerPublicKeySha256,
                current.IssuerPublicKeySha256, StringComparison.Ordinal) ||
            !string.Equals(preview.VerifiedSubject.GetRawText(),
                current.VerifiedSubject.GetRawText(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "An unchanged, live, authenticated full-disclosure preview and issuer status are required.",
                nameof(preview));
        }

        string vp = JwtVcJsonPinnedDidWebIssuerPresentation.Create(
            authenticatedChallenge, credentialJwt, preview.TrustedIssuerDid,
            preview.TrustedVerificationMethodId, independentlyPinnedIssuerPublicKey,
            preview.ExpectedIssuerName, preview.ExpectedCredentialId,
            preview.ExpectedCredentialType, preview.ExpectedSubjectContextUri,
            preview.HolderDid, holderSeed, clock);

        // Status or verifier challenge may expire during holder signing. Never
        // return a proof represented as status-gated after either expiry.
        DateTimeOffset afterSigning = clock.GetUtcNow();
        if (afterSigning >= authenticatedChallenge.ExpiresAt ||
            JwtVcJsonPinnedDidWebIssuerStatus.CheckSignedStatus(
                statusJwt, credentialJwt, preview.TrustedIssuerDid,
                preview.TrustedVerificationMethodId,
                independentlyPinnedIssuerPublicKey.ToArray(), afterSigning) !=
                RevocationSnapshotCheckResult.NotListed)
        {
            throw new ArgumentException(
                "The authenticated challenge or signed issuer observation expired during holder signing.",
                nameof(statusJwt));
        }

        return vp;
    }

    private static bool ValidRequest(
        PresentationChallenge challenge, string trustedIssuerDid,
        string expectedCredentialType, Uri expectedContext, DateTimeOffset now) =>
        string.Equals(challenge.TrustedIssuerDid, trustedIssuerDid,
            StringComparison.Ordinal) &&
        PresentationChallengePolicy.IsValidNonce(challenge.Nonce) &&
        !string.IsNullOrWhiteSpace(challenge.Audience) &&
        challenge.Audience.Length <= PresentationChallengePolicy.MaximumIdentifierLength &&
        challenge.ExpiresAt > now &&
        challenge.ExpiresAt <= now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) &&
        (challenge.CredentialType is null) == (challenge.SubjectContextUri is null) &&
        (challenge.CredentialType is null ||
         string.Equals(challenge.CredentialType, expectedCredentialType,
             StringComparison.Ordinal)) &&
        (challenge.SubjectContextUri is null ||
         string.Equals(challenge.SubjectContextUri.AbsoluteUri, expectedContext.AbsoluteUri,
             StringComparison.Ordinal));

    private static string Digest(string compactJwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(compactJwt)));
}
