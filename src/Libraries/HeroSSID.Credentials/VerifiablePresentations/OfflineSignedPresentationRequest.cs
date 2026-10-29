using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Verifier-signed, pinned-identity request before full disclosure.</summary>
public static class OfflineSignedPresentationRequest
{
    /// <summary>Signs a verifier-issued request with its distinct DID key.</summary>
    public static string Create(PresentationChallenge challenge, string verifierDid, byte[] verifierPrivateKey, TimeProvider clock) =>
        throw new NotSupportedException("Signed verifier requests are not yet implemented.");

    /// <summary>Checks an authentic signed request against locally trusted verifier policy.</summary>
    public static bool TryRead(string requestJwt, string expectedVerifierDid, string expectedAudience,
        TimeProvider clock, out PresentationChallenge? challenge)
    {
        challenge = null;
        return false;
    }

    /// <summary>Only permits a holder signature after independently checking the verifier request.</summary>
    public static string CreatePresentation(string requestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string holderDid, byte[] holderPrivateKey, TimeProvider clock) =>
        throw new NotSupportedException("Signed verifier requests are not yet implemented.");
}
