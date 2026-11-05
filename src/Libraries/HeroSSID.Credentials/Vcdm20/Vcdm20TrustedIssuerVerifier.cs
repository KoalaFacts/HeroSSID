using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Explicit verifier-owned issuer allowlist for a bounded VC2 key transition.
/// Verification never infers issuer trust from the JWT or a successor proof.
/// </summary>
public static class Vcdm20TrustedIssuerVerifier
{
    private const int MaximumTrustedIssuers = 16;

    /// <summary>
    /// Verify a direct VC2 JWT against a small, independently enrolled set of
    /// issuer did:key values. Both the historical and replacement issuer must
    /// already be trusted by the relying verifier; a cross-signed key successor
    /// proof never silently grants trust. The actual verified signer and claims
    /// are returned only after the existing signature, holder, type, vocabulary
    /// and lifetime checks succeed. This is not holder-key proof, revocation,
    /// real-world identity verification, delegation or business authorization.
    /// </summary>
    public static bool TryVerify(
        string issuerSignedJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(issuerSignedJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // Reject an unbounded or empty verifier trust policy before examining
        // untrusted credentials. Snapshot caller-owned mutable collections once.
        if (trustedIssuerDids.Count is < 1 or > MaximumTrustedIssuers)
        {
            return false;
        }

        string[] issuers = trustedIssuerDids.ToArray();
        if (issuers.Length != trustedIssuerDids.Count)
        {
            return false;
        }

        // Validate the ENTIRE trust policy before accepting even one authentic
        // credential. Duplicate, invalid or ambiguous entries fail closed.
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in issuers)
        {
            if (string.IsNullOrWhiteSpace(did) ||
                !unique.Add(did) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _))
            {
                return false;
            }
        }

        // Do not select an issuer from an unverified 'issuer' or JOSE 'kid'
        // claim. Every candidate comes solely from the verifier's own pins.
        foreach (string did in issuers)
        {
            if (Vcdm20JoseCredential.TryVerify(
                issuerSignedJwt, did, expectedHolderDid, expectedCredentialType,
                expectedSubjectContextUri, now, out var verified))
            {
                verifiedIssuerDid = did;
                verifiedSubject = verified;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Opt-in verification of an issuer-signed VC2 credential with a top-level
    /// identifier, additionally pinned to one exact verifier-approved credential
    /// URI and an independently enrolled historical/current issuer allowlist.
    /// An issuer signature does not establish issuer trust, revocation status,
    /// holder control or business authorization.
    /// </summary>
    public static bool TryVerifyWithId(
        string issuerSignedJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, Uri expectedCredentialId,
        DateTimeOffset now, out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(issuerSignedJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);

        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // The caller pins a canonical HTTPS identifier independently of the
        // credential. A signed identifier alone must never grant issuer trust.
        if (!expectedCredentialId.IsAbsoluteUri ||
            !string.Equals(expectedCredentialId.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(expectedCredentialId.Host) ||
            !string.IsNullOrEmpty(expectedCredentialId.UserInfo) ||
            expectedCredentialId.AbsoluteUri.Length > 2_048 ||
            trustedIssuerDids.Count is < 1 or > MaximumTrustedIssuers)
        {
            return false;
        }

        // Snapshot the caller-owned trust set and reject the whole policy if
        // any issuer is malformed or duplicated, even when another is valid.
        string[] issuers = trustedIssuerDids.ToArray();
        if (issuers.Length != trustedIssuerDids.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in issuers)
        {
            if (string.IsNullOrWhiteSpace(did) ||
                !unique.Add(did) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _))
            {
                return false;
            }
        }

        // Only attempt issuers already pinned by the relying verifier.
        // Never promote the untrusted JWT's 'issuer' or 'kid' into a trust pin.
        string expectedId = expectedCredentialId.AbsoluteUri;
        foreach (string did in issuers)
        {
            if (Vcdm20JoseCredential.TryVerifyWithId(
                issuerSignedJwt, did, expectedHolderDid, expectedCredentialType,
                expectedSubjectContextUri, now, out JsonElement subject,
                out string? signedId) &&
                string.Equals(signedId, expectedId, StringComparison.Ordinal))
            {
                verifiedIssuerDid = did;
                verifiedSubject = subject;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Opt-in relying-party claim policy for an exactly pinned VC2 identifier.
    /// Only matching signed top-level string claims may be released; neither
    /// a valid signature nor a claim value grants business authorization.
    /// </summary>
    public static bool TryVerifyWithIdAndRequiredClaims(
        string issuerSignedJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredSubjectClaims,
        DateTimeOffset now, out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        throw new NotSupportedException("Claim policy verification not implemented.");
    }
}
