using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Result of independently verifying issuer and holder signatures with an atomic challenge.</summary>
public enum JwtVcJsonPresentationCheckResult
{
    /// <summary>Forged, malformed, untrusted, expired, misbound or already consumed proof.</summary>
    Invalid,

    /// <summary>Verified issuer statement, holder signature and challenge; status remains unchecked.</summary>
    SignedButStatusUnchecked
}

/// <summary>
/// Bounded full-disclosure JWT VP containing a genuine nested VC1.1 jwt_vc_json JWT.
/// Not a hosted OpenID4VP exchange or third-party wallet conformance result.
/// </summary>
public static class JwtVcJsonPresentation
{
    /// <summary>Holder verifies the signed request and issuer before signing an independently consented presentation.</summary>
    public static string Create(string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedSubjectContextUri,
        string holderDid, byte[] holderSeed, TimeProvider clock)
    {
        throw new NotSupportedException("Test-first: JWT VC JSON holder presentation not implemented.");
    }

    /// <summary>Verifier checks both real signatures and consumes the one-use challenge before releasing claims.</summary>
    public static JwtVcJsonPresentationCheckResult Check(string presentationJwt,
        Guid verifierTenantId, string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Test-first: JWT VC JSON holder proof verifier not implemented.");
    }
}
