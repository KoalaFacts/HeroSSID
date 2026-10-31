using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Distinguishes verifier-owned emergency denial from issuer-signed private
/// revocation, unsuccessful validation, and status-unchecked issuer statements.
/// </summary>
public enum Vcdm20VerifierPolicyResult
{
    /// <summary>Invalid trust policy, credential, or required issuer status.</summary>
    Invalid,

    /// <summary>Independent verifier denied the exact authentic original JWT.</summary>
    DeniedByVerifier,

    /// <summary>The actual issuer's authentic snapshot listed the JWT as revoked.</summary>
    IssuerReportedRevoked,

    /// <summary>Authentic issuer statement; status has not been checked.</summary>
    SignedButStatusUnchecked,

    /// <summary>Authentic issuer snapshot omitted the JWT; completeness is unproven.</summary>
    SignedNotListed
}

/// <summary>
/// Opt-in independent relying-party emergency denial of real Ed25519-signed
/// direct VC2 JWTs. Caller owns and distributes its entire bounded SHA-256
/// policy; this library neither registers users nor provides network revocation.
/// </summary>
public static class Vcdm20VerifierDenylist
{
    private const int MaximumDeniedCredentialDigests = 256;

    /// <summary>
    /// Verify the original issuer statement against the caller's independently
    /// pinned historical/current issuer DIDs and apply a canonical exact-JWT
    /// SHA-256 denylist. No issuer or subject is released on a rejection.
    /// Signing does not prove holder possession, identity, consent or authority.
    /// </summary>
    public static Vcdm20VerifierPolicyResult Check(
        string credentialJwt, IReadOnlyCollection<string> trustedIssuerDids,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject) =>
        CheckCore(credentialJwt, null, trustedIssuerDids, deniedCredentialSha256,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedIssuerDid, out verifiedSubject);

    /// <summary>
    /// Additionally require a genuine, current, private 60-second status
    /// snapshot from the actual signer of this original credential. A clean
    /// signed list cannot override a verifier's independent emergency denial.
    /// Neither outcome asserts live non-revocation or list completeness.
    /// </summary>
    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        return CheckCore(credentialJwt, revocationSnapshotJwt,
            trustedIssuerDids, deniedCredentialSha256,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedIssuerDid, out verifiedSubject);
    }

    private static Vcdm20VerifierPolicyResult CheckCore(
        string credentialJwt, string? revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // A verifier-owned security policy is not a best-effort hint.
        // Snapshot the entire mutable collection and fail on malformed,
        // duplicated or oversized entries, including entries after a match.
        if (deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        string[] denied = deniedCredentialSha256.ToArray();
        if (denied.Length != deniedCredentialSha256.Count)
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in denied)
        {
            if (!IsCanonicalDigest(digest) || !unique.Add(digest))
            {
                return Vcdm20VerifierPolicyResult.Invalid;
            }
        }

        // Do not allow a mere digest match to authenticate an attacker token.
        // All trusted issuers are independently enrolled by the relying party,
        // and the actual signature, holder, type, HTTPS context and time must
        // validate BEFORE any DeniedByVerifier result can be reported.
        if (!Vcdm20TrustedIssuerVerifier.TryVerify(
                credentialJwt, trustedIssuerDids, expectedHolderDid,
                expectedCredentialType, expectedSubjectContextUri, now,
                out string authenticIssuer, out var authenticatedSubject))
        {
            return Vcdm20VerifierPolicyResult.Invalid;
        }

        var positiveStatus = Vcdm20VerifierPolicyResult.SignedButStatusUnchecked;
        if (revocationSnapshotJwt is not null)
        {
            Vcdm20RevocationCheckResult signedStatus = Vcdm20RevocationSnapshot.Check(
                revocationSnapshotJwt, credentialJwt, authenticIssuer, now);
            if (signedStatus == Vcdm20RevocationCheckResult.Revoked)
            {
                return Vcdm20VerifierPolicyResult.IssuerReportedRevoked;
            }

            if (signedStatus != Vcdm20RevocationCheckResult.SignedNotListed)
            {
                return Vcdm20VerifierPolicyResult.Invalid;
            }

            positiveStatus = Vcdm20VerifierPolicyResult.SignedNotListed;
        }

        string digestOfOriginalJwt = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));
        if (unique.Contains(digestOfOriginalJwt))
        {
            return Vcdm20VerifierPolicyResult.DeniedByVerifier;
        }

        // Release the authentic issuer and subject only after all independent
        // trust, same-issuer status (when required), and local denial checks.
        verifiedIssuerDid = authenticIssuer;
        verifiedSubject = authenticatedSubject;
        return positiveStatus;
    }

    private static bool IsCanonicalDigest(string? value) =>
        value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
