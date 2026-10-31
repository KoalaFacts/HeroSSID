using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Result of a verifier-owned emergency denial decision, distinct from
/// what a separate issuer-signed private status snapshot reports.
/// </summary>
public enum JwtVcJsonVerifierPolicyResult
{
    /// <summary>Untrusted, malformed or expired credential, or invalid policy.</summary>
    Invalid,

    /// <summary>Verifier independently blocked the exact authenticated compact JWT.</summary>
    DeniedByVerifier,

    /// <summary>Actual issuer's signed private snapshot reported revocation.</summary>
    IssuerReportedRevoked,

    /// <summary>Issuer authenticated; status was not checked.</summary>
    SignedButStatusUnchecked,

    /// <summary>Issuer's private signed snapshot did not list the JWT; completeness unproven.</summary>
    SignedNotListed
}

/// <summary>
/// Verifier-owned, exact-original-JWT emergency denial for active and retired
/// issuer credentials. This is an independent local trust policy, not a
/// network revocation registry, wallet or holder-key-control proof.
/// </summary>
public static class JwtVcJsonVerifierDenylist
{
    private const int MaximumDeniedCredentialDigests = 256;

    /// <summary>
    /// Verify real Ed25519 provenance and all caller-owned issuer/holder,
    /// type/context/time policies, then apply an independently provisioned
    /// exact-JWT SHA-256 denylist before disclosing any issuer or subject.
    /// A pin in the RETIRED credential inventory does not override denial.
    /// </summary>
    public static JwtVcJsonVerifierPolicyResult Check(
        string credentialJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject) =>
        CheckCore(credentialJwt, null, activeIssuerDids, retiredCredentialPins,
            deniedCredentialSha256, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedIssuerDid, out verifiedSubject);

    /// <summary>
    /// Additionally require a genuine same-issuer 60-second private status
    /// snapshot. A clean issuer snapshot cannot override independent local
    /// denial. Neither signed absence nor local non-denial proves live status.
    /// </summary>
    public static JwtVcJsonVerifierPolicyResult CheckWithStatus(
        string credentialJwt,
        string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        return CheckCore(credentialJwt, revocationSnapshotJwt,
            activeIssuerDids, retiredCredentialPins, deniedCredentialSha256,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedIssuerDid, out verifiedSubject);
    }

    private static JwtVcJsonVerifierPolicyResult CheckCore(
        string credentialJwt,
        string? revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(activeIssuerDids);
        ArgumentNullException.ThrowIfNull(retiredCredentialPins);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // Treat every entry as verifier-owned security policy, not as a hint.
        // Snapshot and validate the ENTIRE list even when the first entry
        // already blocks this token; malformed/duplicate later entries fail.
        if (deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return JwtVcJsonVerifierPolicyResult.Invalid;
        }

        string[] denied = deniedCredentialSha256.ToArray();
        if (denied.Length != deniedCredentialSha256.Count)
        {
            return JwtVcJsonVerifierPolicyResult.Invalid;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in denied)
        {
            if (!IsCanonicalDigest(digest) || !unique.Add(digest))
            {
                return JwtVcJsonVerifierPolicyResult.Invalid;
            }
        }

        // Authenticating the issuer and holder policy BEFORE applying local
        // denial prevents an arbitrary unverified token from being reported
        // as a revoked/denied issuer credential. Retired acceptance itself
        // still requires a separately registered exact signed-JWT fingerprint.
        JwtVcJsonTrustedIssuerCheckResult checkedResult =
            revocationSnapshotJwt is null
                ? JwtVcJsonRetiredIssuerVerifier.Check(
                    credentialJwt, activeIssuerDids, retiredCredentialPins,
                    expectedHolderDid, expectedCredentialType,
                    expectedSubjectContextUri, now, out var actualIssuerDid,
                    out var actualSubject)
                : JwtVcJsonRetiredIssuerVerifier.CheckWithStatus(
                    credentialJwt, revocationSnapshotJwt,
                    activeIssuerDids, retiredCredentialPins,
                    expectedHolderDid, expectedCredentialType,
                    expectedSubjectContextUri, now, out actualIssuerDid,
                    out actualSubject);

        if (checkedResult == JwtVcJsonTrustedIssuerCheckResult.Revoked)
        {
            return JwtVcJsonVerifierPolicyResult.IssuerReportedRevoked;
        }

        if (checkedResult is not (JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked
            or JwtVcJsonTrustedIssuerCheckResult.SignedNotListed))
        {
            return JwtVcJsonVerifierPolicyResult.Invalid;
        }

        string originalDigest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));
        if (unique.Contains(originalDigest))
        {
            return JwtVcJsonVerifierPolicyResult.DeniedByVerifier;
        }

        verifiedIssuerDid = actualIssuerDid;
        verifiedSubject = actualSubject;
        return checkedResult == JwtVcJsonTrustedIssuerCheckResult.SignedNotListed
            ? JwtVcJsonVerifierPolicyResult.SignedNotListed
            : JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked;
    }

    private static bool IsCanonicalDigest(string? value) =>
        value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
