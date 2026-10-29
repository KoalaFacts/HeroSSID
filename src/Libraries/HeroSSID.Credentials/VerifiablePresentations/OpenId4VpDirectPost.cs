namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>A signed OpenID4VP 1.0 direct_post request accepted by this bounded development profile.</summary>
public sealed record OpenId4VpDirectPostRequest(
    PresentationChallenge Challenge, string ClientId, string ResponseUri);

/// <summary>
/// OpenID4VP 1.0 direct_post exchange for one full-disclosure jwt_vc_json credential.
/// This does not implement wallet discovery, request_uri, encryption, or other formats.
/// </summary>
public static class OpenId4VpDirectPost
{
    /// <summary>Signs a verifier-owned challenge as a JAR request using did:key and Ed25519.</summary>
    public static string CreateSignedRequest(PresentationChallenge challenge, string verifierDid,
        byte[] verifierPrivateKey, string responseUri, TimeProvider clock) =>
        throw new NotSupportedException("OpenID4VP 1.0 direct_post is not implemented.");

    /// <summary>Validates an OpenID4VP 1.0 signed request against independently pinned verifier policy.</summary>
    public static bool TryReadSignedRequest(string requestJwt, string expectedVerifierDid,
        string expectedResponseUri, TimeProvider clock, out OpenId4VpDirectPostRequest? request)
    {
        request = null;
        return false;
    }

    /// <summary>
    /// After the holder's full-disclosure consent, creates the form-encoded response.
    /// No holder key material is retained or remotely shared.
    /// </summary>
    public static string CreateHolderResponseForm(string requestJwt, string expectedVerifierDid,
        string expectedResponseUri, string credentialJwt, string holderDid, byte[] holderPrivateKey,
        TimeProvider clock) =>
        throw new NotSupportedException("OpenID4VP 1.0 direct_post is not implemented.");

    /// <summary>Checks the direct_post body using the verifier's own one-use challenge and issuer status.</summary>
    public static OfflinePresentationCheckResult CheckResponseForm(string form, string snapshotJwt,
        Guid verifierTenantId, string expectedClientId, string expectedNonce,
        IPresentationChallengeStore challenges, TimeProvider clock) =>
        OfflinePresentationCheckResult.Invalid;
}
