using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>The verifier-authenticated details of a bounded JWT VC JSON direct_post request.</summary>
public sealed record JwtVcJsonDirectPostRequest(
    PresentationChallenge Challenge, string ClientId, Uri ResponseUri, string CredentialType);

/// <summary>Single-credential OpenID4VP 1.0 jwt_vc_json direct_post transport under explicit HeroSSID trust policy.</summary>
public static class OpenId4VpJwtVcJsonDirectPost
{
    /// <summary>Signs a retained challenge using the verifier's did:key Ed25519 private key.</summary>
    public static string CreateSignedRequest(PresentationChallenge challenge, string verifierDid,
        byte[] verifierPrivateKey, Uri responseUri, string credentialType,
        Uri subjectContextUri, TimeProvider clock) => throw new NotSupportedException();

    /// <summary>Validates a signed verifier request against independently pinned identity, callback and vocabulary.</summary>
    public static bool TryReadSignedRequest(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, out JwtVcJsonDirectPostRequest? request) => throw new NotSupportedException();

    /// <summary>Returns a holder-signed JWT VC 1.1 VP encoded for direct_post after application-controlled consent.</summary>
    public static string CreateHolderResponseForm(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri,
        string credentialJwt, string holderDid, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException();

    /// <summary>Verifies the issuer and holder signatures and atomically consumes the verifier-owned nonce.</summary>
    public static JwtVcJsonPresentationCheckResult CheckResponseForm(string form, Guid verifierTenantId,
        string expectedClientId, string expectedNonce, string expectedCredentialType,
        Uri expectedSubjectContextUri, IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject) => throw new NotSupportedException();
}
