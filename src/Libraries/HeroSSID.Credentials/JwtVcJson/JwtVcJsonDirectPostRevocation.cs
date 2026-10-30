using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Verify one exact issuer-signed VC1.1 in a holder's one-use direct_post
/// against an issuer-signed, bounded revocation export. The verifier must
/// independently supply its trusted issuer policy and authoritative status.
/// </summary>
public static class JwtVcJsonDirectPostRevocation
{
    /// <summary>
    /// Accept signed subject claims only when an authentic, fresh issuer
    /// snapshot does not list the actual credential in the holder's proof.
    /// NotListed is NOT a live non-revocation guarantee or authorization.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckResponseForm(
        string form, string snapshotJwt, Guid verifierTenantId,
        string expectedClientId, string expectedNonce, string expectedCredentialType,
        Uri expectedSubjectContextUri, IPresentationChallengeStore challenges,
        TimeProvider clock, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Status-aware direct_post verification is not implemented.");
    }
}
