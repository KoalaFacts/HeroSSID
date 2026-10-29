using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>Holder-owned full-disclosure VCDM 2.0 EnvelopedVerifiableCredential presentation.</summary>
public enum Vcdm20PresentationCheckResult
{
    /// <summary>Invalid or previously consumed challenge or signatures.</summary>
    Invalid,
    /// <summary>Issuer and holder signatures and one-use challenge verified; revocation was NOT checked.</summary>
    SignedButStatusUnchecked
}

/// <summary>Opt-in VC2 holder presentation exchange; not a wallet, status service or conformance certification.</summary>
public static class Vcdm20JosePresentation
{
    /// <summary>Requires a genuine request from an independently pinned verifier and prior user consent.</summary>
    public static string Create(
        string signedRequestJwt, string trustedVerifierDid, string expectedAudience,
        string credentialJwt, string expectedCredentialType, Uri expectedContextUri,
        string holderDid, byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Test-first scaffold; implement real Ed25519 and VC2 envelope.");

    /// <summary>Consumes a verifier-owned nonce atomically; success does not establish non-revocation.</summary>
    public static Vcdm20PresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return Vcdm20PresentationCheckResult.Invalid;
    }
}
