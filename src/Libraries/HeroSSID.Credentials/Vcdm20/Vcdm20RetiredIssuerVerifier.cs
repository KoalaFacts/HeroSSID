using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifier-registered SHA-256 of the EXACT original compact VC2 JWT from a
/// retired issuer. A pin does not prove when the credential was originally issued.
/// </summary>
public sealed record Vcdm20RetiredCredentialPin(string IssuerDid, string CredentialSha256);

/// <summary>
/// Opt-in verifier-owned VC2 key retirement. Active issuer DIDs may sign new
/// credentials; an old DID may authenticate only exact independently pinned
/// original signed JWTs. This never auto-promotes a successor DID or verifies
/// real identity, holder possession, consent, or business authorization.
/// </summary>
public static class Vcdm20RetiredIssuerVerifier
{
    private const int MaximumActiveIssuers = 16;
    private const int MaximumDistinctIssuers = 16;
    private const int MaximumRetiredCredentialPins = 256;
    private const int MaximumDidLength = 255;
    private const int MaximumCredentialLength = 65_536;

    /// <summary>
    /// Verify an independently trusted active issuer or an exact pre-registered
    /// retired issuer JWT, including original Ed25519 signature, holder, VC2
    /// vocabulary, type and lifetime. No status is checked by this overload.
    /// Neither a signed iat nor a SHA-256 pin establishes historical issuance.
    /// </summary>
    public static Vcdm20VerifierPolicyResult Check(
        string credentialJwt, IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        CheckCore(credentialJwt, null, activeIssuerDids, retiredCredentialPins,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedIssuerDid, out verifiedSubject);

    /// <summary>
    /// Also require the actual issuer's authentic 60-second private status JWT.
    /// SignedNotListed does not establish completeness, live non-revocation or
    /// trust in a compromised retired key's status publication.
    /// </summary>
    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        return CheckCore(credentialJwt, revocationSnapshotJwt,
            activeIssuerDids, retiredCredentialPins, expectedHolderDid,
            expectedCredentialType, expectedSubjectContextUri, now,
            out verifiedIssuerDid, out verifiedSubject);
    }

    /// <summary>
    /// Require signed issuer status observed no earlier than an independently
    /// chosen verifier incident cutoff, in addition to exact retired JWT pins.
    /// An issuer signature does not prove completeness or live non-revocation.
    /// </summary>
    public static Vcdm20VerifierPolicyResult CheckWithStatusAfterObservationCutoff(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        DateTimeOffset minimumObservedAt,
        out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        throw new NotSupportedException("Status observation cutoff not implemented");

    private static Vcdm20VerifierPolicyResult CheckCore(
        string credentialJwt, string? revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(activeIssuerDids);
        ArgumentNullException.ThrowIfNull(retiredCredentialPins);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumCredentialLength ||
            activeIssuerDids.Count > MaximumActiveIssuers ||
            retiredCredentialPins.Count > MaximumRetiredCredentialPins ||
            activeIssuerDids.Count == 0 && retiredCredentialPins.Count == 0)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        // Snapshot and validate the entire caller-owned policy, including
        // entries after a match, before trusting a credential or status.
        string[] active = activeIssuerDids.ToArray();
        Vcdm20RetiredCredentialPin[] retired = retiredCredentialPins.ToArray();
        if (active.Length != activeIssuerDids.Count ||
            retired.Length != retiredCredentialPins.Count)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        var activeDids = new HashSet<string>(StringComparer.Ordinal);
        var allDids = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in active)
        {
            if (!ValidDid(did) || !activeDids.Add(did))
            {
                return Vcdm20VerifierPolicyResult.Invalid;
            }

            allDids.Add(did);
        }

        var exactPins = new HashSet<string>(StringComparer.Ordinal);
        foreach (Vcdm20RetiredCredentialPin pin in retired)
        {
            if (pin is null || !ValidDid(pin.IssuerDid) ||
                activeDids.Contains(pin.IssuerDid) ||
                !ValidDigest(pin.CredentialSha256) ||
                !exactPins.Add(pin.CredentialSha256))
            {
                // Overlap would bypass exact-JWT retirement; duplicate hashes
                // could bind the same credential to two different issuers.
                return Vcdm20VerifierPolicyResult.Invalid;
            }

            allDids.Add(pin.IssuerDid);
        }

        if (allDids.Count > MaximumDistinctIssuers)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        // Never select trust using an unauthenticated issuer or JOSE kid.
        string authenticIssuer = string.Empty;
        JsonElement authenticatedSubject = default;
        bool authenticated = active.Length > 0 &&
            Vcdm20TrustedIssuerVerifier.TryVerify(
                credentialJwt, active, expectedHolderDid, expectedCredentialType,
                expectedSubjectContextUri, now,
                out authenticIssuer, out authenticatedSubject);

        if (!authenticated && retired.Length > 0)
        {
            string digest = Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));
            foreach (Vcdm20RetiredCredentialPin pin in retired)
            {
                if (!string.Equals(digest, pin.CredentialSha256, StringComparison.Ordinal))
                {
                    continue;
                }

                // Hash equality permits TRYING an independently registered DID.
                // It never substitutes for real issuer signature/policy checks.
                if (!Vcdm20JoseCredential.TryVerify(credentialJwt, pin.IssuerDid,
                    expectedHolderDid, expectedCredentialType,
                    expectedSubjectContextUri, now, out authenticatedSubject))
                {
                    return Vcdm20VerifierPolicyResult.Invalid;
                }

                authenticIssuer = pin.IssuerDid;
                authenticated = true;
                break;
            }
        }

        if (!authenticated)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        var result = Vcdm20VerifierPolicyResult.SignedButStatusUnchecked;
        if (revocationSnapshotJwt is not null)
        {
            Vcdm20RevocationCheckResult status = Vcdm20RevocationSnapshot.Check(
                revocationSnapshotJwt, credentialJwt, authenticIssuer, now);
            if (status == Vcdm20RevocationCheckResult.Revoked)
            {
                return Vcdm20VerifierPolicyResult.IssuerReportedRevoked;
            }

            if (status != Vcdm20RevocationCheckResult.SignedNotListed)
            {
                return Vcdm20VerifierPolicyResult.Invalid;
            }

            result = Vcdm20VerifierPolicyResult.SignedNotListed;
        }

        verifiedIssuerDid = authenticIssuer;
        verifiedSubject = authenticatedSubject;
        return result;
    }

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= MaximumDidLength &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _);

    private static bool ValidDigest(string? digest) =>
        digest is { Length: 64 } &&
        digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
