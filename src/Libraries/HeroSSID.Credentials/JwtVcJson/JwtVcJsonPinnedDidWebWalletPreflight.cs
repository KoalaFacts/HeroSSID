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
/// An authenticated did:web Wallet preview and its exact locally approved
/// emergency policy. A preview never proves that a human consented.
/// </summary>
public sealed record JwtVcJsonPinnedDidWebWalletEmergencyPreview(
    JwtVcJsonPinnedDidWebWalletPreview Disclosure, string DenylistSha256);

/// <summary>
/// Holder-side, SDK-only did:web VC1.1 full-disclosure preflight.
/// The integrating wallet must independently authenticate the verifier's
/// request and issuer trust pins, display every claim and obtain actual
/// informed consent. No signing, nonce consumption or wallet UI occurs here.
/// </summary>
public static class JwtVcJsonPinnedDidWebWalletPreflight
{


    /// <summary>
    /// Opt-in: check a Wallet-owned exact-original-JWT emergency denylist
    /// BEFORE revealing full subject claims. Independently pinned issuer
    /// signature and non-revoked status remain mandatory. The list is local
    /// incident policy, not an issuer-signed revocation statement.
    /// </summary>
    public static bool TryPrepareWithEmergencyDenylist(
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid,
        IReadOnlyCollection<string> deniedCredentialSha256, TimeProvider clock,
        out JwtVcJsonPinnedDidWebWalletEmergencyPreview? preview)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        preview = null;

        if (credentialJwt.Length > MaximumCredentialLength ||
            !TrySnapshotDenylist(deniedCredentialSha256, out string[] denied) ||
            Array.BinarySearch(denied, Digest(credentialJwt),
                StringComparer.Ordinal) >= 0)
        {
            return false;
        }

        string policyHash = HashDenylist(denied);
        if (!TryPrepare(authenticatedChallenge, credentialJwt, statusJwt,
                trustedIssuerDid, trustedVerificationMethodId,
                independentlyPinnedIssuerPublicKey, expectedIssuerName,
                expectedCredentialId, expectedCredentialType,
                expectedSubjectContextUri, holderDid, clock, out var disclosure) ||
            disclosure is null ||
            // The source collection may have changed during signature checks.
            !TrySnapshotDenylist(deniedCredentialSha256, out string[] latest) ||
            !string.Equals(policyHash, HashDenylist(latest),
                StringComparison.Ordinal) ||
            Array.BinarySearch(latest, disclosure.CredentialSha256,
                StringComparer.Ordinal) >= 0)
        {
            return false;
        }

        preview = new JwtVcJsonPinnedDidWebWalletEmergencyPreview(
            disclosure, policyHash);
        return true;
    }

    /// <summary>
    /// After the wallet's own informed-consent step, require that its entire
    /// current authoritative denylist is unchanged, the original credential
    /// remains allowed, and the issuer/status/challenge/subject preview still
    /// verifies before releasing a holder-signed VP. This is not consent proof.
    /// </summary>
    public static string CreateAfterEmergencyDenylistPreview(
        JwtVcJsonPinnedDidWebWalletEmergencyPreview preview,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, byte[] independentlyPinnedIssuerPublicKey,
        IReadOnlyCollection<string> deniedCredentialSha256,
        byte[] holderSeed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        JwtVcJsonPinnedDidWebWalletPreview? prior = preview.Disclosure;
        if (prior is null ||
            !TryPrepareWithEmergencyDenylist(authenticatedChallenge,
                credentialJwt, statusJwt, prior.TrustedIssuerDid,
                prior.TrustedVerificationMethodId, independentlyPinnedIssuerPublicKey,
                prior.ExpectedIssuerName, prior.ExpectedCredentialId,
                prior.ExpectedCredentialType, prior.ExpectedSubjectContextUri,
                prior.HolderDid, deniedCredentialSha256, clock, out var current) ||
            current is null ||
            !string.Equals(preview.DenylistSha256, current.DenylistSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "An unchanged Wallet emergency policy and current authenticated issuer status are required.",
                nameof(preview));
        }

        // The existing signer re-verifies the true original issuer JWT,
        // same-issuer status, exact displayed claims, authenticated challenge,
        // and real holder Ed25519 seed (including expiry after signing).
        string presentation = CreateAfterPreview(prior, authenticatedChallenge,
            credentialJwt, statusJwt, independentlyPinnedIssuerPublicKey,
            holderSeed, clock);

        // If incident policy changed while signing, do not return the proof.
        // Applications must supply their current authoritative policy snapshot
        // and serialize changes with the consent/send decision.
        if (!TrySnapshotDenylist(deniedCredentialSha256, out string[] after) ||
            !string.Equals(preview.DenylistSha256, HashDenylist(after),
                StringComparison.Ordinal) ||
            Array.BinarySearch(after, Digest(credentialJwt),
                StringComparer.Ordinal) >= 0)
        {
            throw new ArgumentException(
                "Wallet emergency policy changed during signing; the presentation must not be sent.",
                nameof(deniedCredentialSha256));
        }

        return presentation;
    }

    private const int MaximumDeniedCredentialDigests = 256;

    private static bool TrySnapshotDenylist(
        IReadOnlyCollection<string> deniedCredentialSha256, out string[] sorted)
    {
        sorted = [];
        if (deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return false;
        }

        string[] copy = deniedCredentialSha256.ToArray();
        if (copy.Length != deniedCredentialSha256.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in copy)
        {
            if (digest is not { Length: 64 } ||
                !digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                !unique.Add(digest))
            {
                return false;
            }
        }

        sorted = unique.OrderBy(static digest => digest,
            StringComparer.Ordinal).ToArray();
        return true;
    }

    private static string HashDenylist(string[] sorted) =>
        Digest(string.Join("\n", sorted));

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
