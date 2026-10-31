using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Verifier-registered SHA-256 of the EXACT original compact signed JWT from
/// a retired Ed25519 did:key. This pin is not evidence of when it was issued.
/// </summary>
public sealed record JwtVcJsonRetiredCredentialPin(string IssuerDid, string CredentialSha256);

/// <summary>
/// Opt-in verifier-owned issuer retirement policy for VC1.1 jwt_vc_json.
/// Active issuer DIDs may sign new credentials; retired DIDs can authenticate
/// ONLY exact pre-enrolled original signed JWTs. This does not recover lost
/// keys, auto-enroll old credentials or establish consent/business authority.
/// </summary>
public static class JwtVcJsonRetiredIssuerVerifier
{
    private const int MaximumActiveIssuers = 16;
    private const int MaximumDistinctIssuers = 16;
    private const int MaximumRetiredCredentialPins = 256;
    private const int MaximumDidLength = 255;
    private const int MaximumCredentialLength = 65_536;

    /// <summary>
    /// Verify a genuine current issuer signature or a separately pinned
    /// original credential from a retired issuer. New/backdated JWTs signed
    /// by a retired key are rejected unless independently enrolled by digest.
    /// Normal holder, type, context, signature and expiry checks still apply.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult Check(
        string credentialJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject) =>
        CheckCore(credentialJwt, null, activeIssuerDids, retiredCredentialPins,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedIssuerDid, out verifiedSubject);

    /// <summary>
    /// Additionally require a valid same-issuer private 60-second signed
    /// revocation snapshot. NotListed never establishes completeness or live
    /// non-revocation; a compromised retired key cannot be a reliable status
    /// authority without independent trust in its status distribution.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string credentialJwt,
        string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        return CheckCore(credentialJwt, revocationSnapshotJwt, activeIssuerDids,
            retiredCredentialPins, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedIssuerDid, out verifiedSubject);
    }

    private static JwtVcJsonTrustedIssuerCheckResult CheckCore(
        string credentialJwt, string? revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
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

        // Do not release signer or subject on any unsuccessful verification.
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumCredentialLength ||
            activeIssuerDids.Count > MaximumActiveIssuers ||
            retiredCredentialPins.Count > MaximumRetiredCredentialPins ||
            activeIssuerDids.Count == 0 && retiredCredentialPins.Count == 0)
        {
            return JwtVcJsonTrustedIssuerCheckResult.Invalid;
        }

        // Snapshot the entire externally controlled policy, then validate
        // ALL entries before any credential signature or status verification.
        string[] active = activeIssuerDids.ToArray();
        JwtVcJsonRetiredCredentialPin[] retired = retiredCredentialPins.ToArray();
        if (active.Length != activeIssuerDids.Count ||
            retired.Length != retiredCredentialPins.Count)
        {
            return JwtVcJsonTrustedIssuerCheckResult.Invalid;
        }

        var activeDids = new HashSet<string>(StringComparer.Ordinal);
        var allDids = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in active)
        {
            if (!ValidDid(did) || !activeDids.Add(did))
            {
                return JwtVcJsonTrustedIssuerCheckResult.Invalid;
            }

            allDids.Add(did);
        }

        var registeredCredentialDigests = new HashSet<string>(StringComparer.Ordinal);
        foreach (JwtVcJsonRetiredCredentialPin pin in retired)
        {
            if (pin is null || !ValidDid(pin.IssuerDid) ||
                activeDids.Contains(pin.IssuerDid) ||
                !ValidDigest(pin.CredentialSha256) ||
                !registeredCredentialDigests.Add(pin.CredentialSha256))
            {
                // Retired and active DIDs must be disjoint: allowing a retired
                // DID in the active set would silently bypass every exact pin.
                return JwtVcJsonTrustedIssuerCheckResult.Invalid;
            }

            allDids.Add(pin.IssuerDid);
        }

        if (allDids.Count > MaximumDistinctIssuers)
        {
            return JwtVcJsonTrustedIssuerCheckResult.Invalid;
        }

        // Active trust is explicit and can accept new valid signed JWTs.
        // A failure here never enrolls an untrusted issuer or reveals claims.
        if (active.Length > 0)
        {
            var activeResult = Verify(credentialJwt, revocationSnapshotJwt, active,
                expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
                now, out verifiedIssuerDid, out verifiedSubject);
            if (activeResult != JwtVcJsonTrustedIssuerCheckResult.Invalid)
            {
                return activeResult;
            }
        }

        // A retired key's authentic signature (including a backdated iat)
        // alone is no longer enough. The exact original signed JWT must have
        // been registered through a separate trusted verifier-owned channel.
        if (retired.Length != 0)
        {
            string digest = Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));
            foreach (JwtVcJsonRetiredCredentialPin pin in retired)
            {
                if (string.Equals(digest, pin.CredentialSha256, StringComparison.Ordinal))
                {
                    return Verify(credentialJwt, revocationSnapshotJwt,
                        [pin.IssuerDid], expectedHolderDid, expectedCredentialType,
                        expectedSubjectContextUri, now,
                        out verifiedIssuerDid, out verifiedSubject);
                }
            }
        }

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        return JwtVcJsonTrustedIssuerCheckResult.Invalid;
    }

    private static JwtVcJsonTrustedIssuerCheckResult Verify(
        string credentialJwt, string? revocationSnapshotJwt,
        IReadOnlyCollection<string> issuerDids, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out string verifiedIssuerDid,
        out JsonElement verifiedSubject) =>
        revocationSnapshotJwt is null
            ? JwtVcJsonTrustedIssuerVerifier.Check(credentialJwt, issuerDids,
                expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
                now, out verifiedIssuerDid, out verifiedSubject)
            : JwtVcJsonTrustedIssuerVerifier.CheckWithStatus(credentialJwt,
                revocationSnapshotJwt, issuerDids, expectedHolderDid,
                expectedCredentialType, expectedSubjectContextUri, now,
                out verifiedIssuerDid, out verifiedSubject);

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= MaximumDidLength &&
        OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _);

    private static bool ValidDigest(string? digest) =>
        digest is { Length: 64 } &&
        digest.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
