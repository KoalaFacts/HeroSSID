using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Result of the combined, single-challenge did:web VC1.1 admission gate.</summary>
public enum JwtVcJsonPinnedDidWebIssuerAdmissionResult
{
    /// <summary>Invalid proof, issuer status, verifier policy or replay.</summary>
    Invalid,

    /// <summary>The verifier's separately managed exact-JWT policy denies disclosure.</summary>
    DeniedByVerifier,

    /// <summary>The actual issuer signed a fresh revoked status for this credential.</summary>
    RevokedByIssuer,

    /// <summary>Issuer and holder verified, local policy clean, issuer status signed not revoked.</summary>
    SignedNotRevoked
}

/// <summary>
/// SDK-only composite did:web VC1.1 admission policy. The caller separately
/// owns its verifier-denial policy and its enrolled issuer pins. Neither the
/// holder nor an untrusted JWT may select those policies. No online status,
/// wallet interoperability, human consent or business authority is implied.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerAdmission
{
    private const int MaximumDeniedCredentialDigests = 256;
    private const int MaximumStatusLength = 8_192;

    /// <summary>
    /// Verify the independently pinned original issuer signature, actual holder
    /// signature, one-use verifier challenge, a fresh issuer-signed exact-JWT
    /// status and a strict verifier-owned exact-JWT denylist, before releasing
    /// any claims. A genuine presentation consumes the nonce exactly once,
    /// including when revoked, locally denied or accompanied by forged status.
    /// Missing status and malformed local policy fail before consumption.
    /// </summary>
    public static JwtVcJsonPinnedDidWebIssuerAdmissionResult Check(
        string presentationJwt, string statusJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(statusJwt);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        // Treat the issuer's status input and the entire verifier-owned local
        // policy as prerequisites. Reject missing status and malformed/duplicate
        // digests without spending a holder's otherwise valid pending request.
        if (string.IsNullOrWhiteSpace(statusJwt) ||
            statusJwt.Length > MaximumStatusLength ||
            deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
        }

        string[] denied = deniedCredentialSha256.ToArray();
        if (denied.Length != deniedCredentialSha256.Count)
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
        }

        var deniedDigests = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in denied)
        {
            if (digest is not { Length: 64 } ||
                !digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                !deniedDigests.Add(digest))
            {
                return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
            }
        }

        // One and only one actual holder+original-issuer signature check and
        // atomic verifier-owned challenge consumption. Do NOT compose the
        // separate public status/denylist entry points: each consumes nonce.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (JwtVcJsonPinnedDidWebIssuerPresentation.Check(
                presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
                trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
                expectedIssuerName, expectedCredentialId, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out JsonElement subject) !=
                JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !JwtVcJsonPinnedDidWebPresentationDenylist.TryGetExactOriginalCredential(
                presentationJwt, out string originalCredentialJwt))
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
        }

        // Signature, issuer DID, method, exact credential hash, signed observed
        // time and 60-second validity are verified with the SAME proven
        // implementation as the issuer-status-only gate. No untrusted status
        // field can pick the issuer key.
        RevocationSnapshotCheckResult status =
            JwtVcJsonPinnedDidWebIssuerStatus.CheckSignedStatus(
                statusJwt, originalCredentialJwt, trustedIssuerDid,
                trustedVerificationMethodId, pinnedKey, clock.GetUtcNow());
        if (status == RevocationSnapshotCheckResult.Invalid)
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
        }

        string credentialDigest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(originalCredentialJwt)));
        if (deniedDigests.Contains(credentialDigest))
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.DeniedByVerifier;
        }

        if (status == RevocationSnapshotCheckResult.Revoked)
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.RevokedByIssuer;
        }

        if (status != RevocationSnapshotCheckResult.NotListed)
        {
            return JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid;
        }

        verifiedSubject = subject;
        return JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked;
    }
}
