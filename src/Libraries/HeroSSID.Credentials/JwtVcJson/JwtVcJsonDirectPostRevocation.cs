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
