using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Independent, offline verification outcome. Neither issuer signature nor
/// a private status export establishes holder control or business authority.
/// </summary>
public enum JwtVcJsonTrustedIssuerCheckResult
{
    Invalid,
    Revoked,
    SignedButStatusUnchecked,
    SignedNotListed
}

/// <summary>
/// Bounded verifier-owned issuer trust across historical/current VC1.1
/// jwt_vc_json did:key issuers. Never trusts JWT iss/kid or key-successor
/// attestations as an issuer enrollment source.
/// </summary>
public static class JwtVcJsonTrustedIssuerVerifier
{
    private const int MaximumTrustedIssuers = 16;
    private const int MaximumJwtLength = 65_536;
    private const int MaximumDidLength = 255;

    /// <summary>
    /// Check real Ed25519 provenance, a verifier-supplied issuer allowlist,
    /// holder DID, HTTPS vocabulary/type policy and time before disclosing
    /// claims. A success has NOT checked revocation, holder possession,
    /// real-world identity, end-user consent or authorization.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult Check(
        string credentialJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        return CheckCore(credentialJwt, null, trustedIssuerDids, expectedHolderDid,
            expectedCredentialType, expectedSubjectContextUri, now,
            withStatus: false, minimumObservedAt: null,
            out verifiedIssuerDid, out verifiedSubject);
    }

    /// <summary>
    /// Additionally require a genuine, fresh, private issuer-signed status
    /// snapshot from the credential's ACTUAL authenticated issuer. Another
    /// independently trusted issuer cannot clear this credential. A signed
    /// absence is not proof of a complete or live revocation registry.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        return CheckCore(credentialJwt, revocationSnapshotJwt, trustedIssuerDids,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, withStatus: true, minimumObservedAt: null,
            out verifiedIssuerDid, out verifiedSubject);
    }

    /// <summary>
    /// After an incident, require a genuine status from the original issuer
    /// observed no earlier than a verifier-owned cutoff. Retains the existing
    /// strict credential validation and zero-claim failure contract.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult CheckWithStatusAfterObservationCutoff(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        DateTimeOffset minimumObservedAt,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(revocationSnapshotJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);

        return CheckCore(credentialJwt, revocationSnapshotJwt, trustedIssuerDids,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, withStatus: true, minimumObservedAt,
            out verifiedIssuerDid, out verifiedSubject);
    }

    private static JwtVcJsonTrustedIssuerCheckResult CheckCore(
        string credentialJwt, string? revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, bool withStatus, DateTimeOffset? minimumObservedAt,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        // Do not release even a previously authenticated issuer identity on
        // an invalid, revoked or status-uncertain verification attempt.
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            credentialJwt.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(expectedHolderDid) ||
            expectedHolderDid.Length > MaximumDidLength ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolderDid, out _) ||
            // An expanded HTTPS credential type is independently pinned by
            // this bounded offline profile, matching the authenticated HTTP
            // multi-issuer contract. Do not infer JSON-LD term definitions.
            string.IsNullOrWhiteSpace(expectedCredentialType) ||
            expectedCredentialType.Length > 128 ||
            expectedCredentialType.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(expectedCredentialType, UriKind.Absolute, out var typeUri) ||
            typeUri.Scheme != Uri.UriSchemeHttps ||
            typeUri.Host.Length == 0 || typeUri.UserInfo.Length != 0 ||
            trustedIssuerDids.Count is < 1 or > MaximumTrustedIssuers ||
            (minimumObservedAt is DateTimeOffset cutoff &&
                (cutoff < DateTimeOffset.UnixEpoch || cutoff > now)) ||
            (withStatus && (string.IsNullOrWhiteSpace(revocationSnapshotJwt) ||
                revocationSnapshotJwt.Length > MaximumJwtLength)))
        {
            return JwtVcJsonTrustedIssuerCheckResult.Invalid;
        }

        // Take one snapshot of caller-owned policy and validate EVERY entry
        // before attempting a signature. A valid first issuer must not hide a
        // malformed, duplicated or non-Ed25519 issuer later in the allowlist.
        string[] issuers = trustedIssuerDids.ToArray();
        if (issuers.Length != trustedIssuerDids.Count)
        {
            return JwtVcJsonTrustedIssuerCheckResult.Invalid;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string issuerDid in issuers)
        {
            if (string.IsNullOrWhiteSpace(issuerDid) ||
                issuerDid.Length > MaximumDidLength ||
                !seen.Add(issuerDid) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _))
            {
                return JwtVcJsonTrustedIssuerCheckResult.Invalid;
            }
        }

        // The untrusted iss/kid fields are never used to enroll or choose a
        // candidate. Each candidate is already in the relying party's list.
        foreach (string issuerDid in issuers)
        {
            if (!JwtVcJsonCredential.TryVerify(credentialJwt, issuerDid,
                    expectedHolderDid, expectedCredentialType,
                    expectedSubjectContextUri, now, out var authenticatedSubject))
            {
                continue;
            }

            if (!withStatus)
            {
                verifiedIssuerDid = issuerDid;
                verifiedSubject = authenticatedSubject;
                return JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked;
            }

            // Bind status to the authentic credential signer, never to an
            // alternative allowlisted DID or the status token's own iss.
            var status = minimumObservedAt is DateTimeOffset statusCutoff
                ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                    revocationSnapshotJwt!, credentialJwt, issuerDid, now, statusCutoff)
                : JwtVcJsonRevocationSnapshot.Check(
                    revocationSnapshotJwt!, credentialJwt, issuerDid, now);
            if (status == RevocationSnapshotCheckResult.Revoked)
            {
                return JwtVcJsonTrustedIssuerCheckResult.Revoked;
            }

            if (status != RevocationSnapshotCheckResult.NotListed)
            {
                return JwtVcJsonTrustedIssuerCheckResult.Invalid;
            }

            verifiedIssuerDid = issuerDid;
            verifiedSubject = authenticatedSubject;
            return JwtVcJsonTrustedIssuerCheckResult.SignedNotListed;
        }

        return JwtVcJsonTrustedIssuerCheckResult.Invalid;
    }
}
