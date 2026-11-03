using System.Net;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Private VC1.1 status-aware direct_post verifier, not standard status-list conformance.</summary>
public static class JwtVcJsonDirectPostRevocation
{
    /// <summary>
    /// Return claims only after issuer JWT, holder signature, one-use challenge
    /// and fresh issuer-authenticated status for that exact JWT all pass.
    /// NotListed is not live non-revocation or business authorization.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckResponseForm(
        string form, string snapshotJwt, Guid verifierTenantId,
        string expectedClientId, string expectedNonce, string expectedCredentialType,
        Uri expectedSubjectContextUri, IPresentationChallengeStore challenges,
        TimeProvider clock, out JsonElement verifiedSubject)
    {
        // Keep the status-gated parser's null contract explicit even when the
        // underlying direct_post verifier delegates to a private strict core.
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;
        if (string.IsNullOrWhiteSpace(snapshotJwt) || snapshotJwt.Length > 65_536 ||
            !PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedClientId, expectedNonce))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        var challenge = challenges.Find(verifierTenantId, expectedClientId, expectedNonce);
        if (challenge is null ||
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, verifierTenantId,
                expectedClientId, expectedNonce, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out var claims) !=
            JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !TryGetCredential(form, out var credential))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        var status = JwtVcJsonRevocationSnapshot.Check(
            snapshotJwt, credential, challenge.TrustedIssuerDid, clock.GetUtcNow());
        if (status == RevocationSnapshotCheckResult.NotListed)
        {
            verifiedSubject = claims;
        }

        return status;
    }


    /// <summary>
    /// Strict opt-in: authentic holder-signed original verifier Request Object
    /// AND the actual issuer's fresh private revocation snapshot are required.
    /// No claims may escape on a failed policy, signature or status check.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckHolderBoundResponseForm(
        string form, string snapshotJwt, string signedRequestJwt,
        string verifierRetainedRequestSha256, string trustedVerifierDid,
        Uri expectedResponseUri, Guid verifierTenantId, string expectedClientId,
        string expectedNonce, string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject) =>
        CheckHolderBoundResponseFormCore(
            form, snapshotJwt, signedRequestJwt, verifierRetainedRequestSha256,
            trustedVerifierDid, expectedResponseUri, verifierTenantId, expectedClientId,
            expectedNonce, expectedCredentialType, expectedSubjectContextUri,
            challenges, clock, null, out verifiedSubject);

    /// <summary>
    /// Strict incident policy: a fresh genuine issuer status must be observed at
    /// or after the independent verifier-owned cutoff. Signed whole-second
    /// observation time is never rounded backward to satisfy a fractional cutoff.
    /// A valid holder proof atomically spends the challenge even for denied status;
    /// invalid future or pre-epoch verifier policy does not spend it.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckHolderBoundResponseFormWithObservationCutoff(
        string form, string snapshotJwt, string signedRequestJwt,
        string verifierRetainedRequestSha256, string trustedVerifierDid,
        Uri expectedResponseUri, Guid verifierTenantId, string expectedClientId,
        string expectedNonce, string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        DateTimeOffset minimumStatusObservedAt, out JsonElement verifiedSubject) =>
        CheckHolderBoundResponseFormCore(
            form, snapshotJwt, signedRequestJwt, verifierRetainedRequestSha256,
            trustedVerifierDid, expectedResponseUri, verifierTenantId, expectedClientId,
            expectedNonce, expectedCredentialType, expectedSubjectContextUri,
            challenges, clock, minimumStatusObservedAt, out verifiedSubject);

    private static RevocationSnapshotCheckResult CheckHolderBoundResponseFormCore(
        string form, string snapshotJwt, string signedRequestJwt,
        string verifierRetainedRequestSha256, string trustedVerifierDid,
        Uri expectedResponseUri, Guid verifierTenantId, string expectedClientId,
        string expectedNonce, string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        DateTimeOffset? minimumStatusObservedAt, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        // Reject absent or oversized status and invalid challenge lookups
        // without spending a legitimate pending verifier challenge.
        if (string.IsNullOrWhiteSpace(snapshotJwt) || snapshotJwt.Length > 65_536 ||
            !PresentationChallengePolicy.IsValidLookup(
                verifierTenantId, expectedClientId, expectedNonce) ||
            (minimumStatusObservedAt is DateTimeOffset cutoff &&
                (cutoff < DateTimeOffset.UnixEpoch || cutoff > clock.GetUtcNow())))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        // Only the verifier-owned challenge determines the trusted issuer for
        // the subsequent status check. Neither the form nor JWT can change it.
        var challenge = challenges.Find(verifierTenantId, expectedClientId, expectedNonce);
        if (challenge is null ||
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                form, signedRequestJwt, verifierRetainedRequestSha256,
                trustedVerifierDid, expectedResponseUri, verifierTenantId,
                expectedClientId, expectedNonce, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out var claims) !=
            JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !TryGetCredential(form, out var credential))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        // The strict bound proof has already atomically consumed the nonce.
        // Never expose its claims unless the REAL issuer's short-lived status
        // authenticates the exact original credential inside that proof.
        DateTimeOffset now = clock.GetUtcNow();
        var status = minimumStatusObservedAt is DateTimeOffset minimum
            ? JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                snapshotJwt, credential, challenge.TrustedIssuerDid, now, minimum)
            : JwtVcJsonRevocationSnapshot.Check(
                snapshotJwt, credential, challenge.TrustedIssuerDid, now);
        if (status == RevocationSnapshotCheckResult.NotListed)
        {
            verifiedSubject = claims;
        }

        return status;
    }

    private static bool TryGetCredential(string form, out string credential)
    {
        credential = string.Empty;
        try
        {
            foreach (string part in form.Split('&'))
            {
                int separator = part.IndexOf('=', StringComparison.Ordinal);
                if (separator < 1 || WebUtility.UrlDecode(part[..separator]) != "vp_token")
                {
                    continue;
                }

                string? vpToken = WebUtility.UrlDecode(part[(separator + 1)..]);
                if (string.IsNullOrEmpty(vpToken))
                {
                    return false;
                }

                using var formJson = JsonDocument.Parse(vpToken, new JsonDocumentOptions { MaxDepth = 8 });
                var entries = formJson.RootElement.GetProperty("jwt_vc_json_credential");
                string holderJwt = entries[0].GetString()!;
                using var holderJson = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(holderJwt));
                credential = holderJson.RootElement.GetProperty("vp")
                    .GetProperty("verifiableCredential")[0].GetString()!;
                return StrictJwtReader.IsCanonicalCompact(credential, 65_536);
            }
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or ArgumentException or InvalidOperationException)
        {
            return false;
        }

        return false;
    }
}
