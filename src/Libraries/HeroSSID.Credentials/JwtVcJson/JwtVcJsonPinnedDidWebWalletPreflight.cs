using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>A full-disclosure wallet preview tied to an authentic issuer-signed exact-VC status.</summary>
public sealed record JwtVcJsonPinnedDidWebWalletPreview(
    PresentationChallenge Challenge, string TrustedIssuerDid,
    string TrustedVerificationMethodId, string ExpectedIssuerName,
    Uri ExpectedCredentialId, string ExpectedCredentialType,
    Uri ExpectedSubjectContextUri, string HolderDid,
    JsonElement VerifiedSubject, string CredentialSha256,
    string StatusSha256, string IssuerPublicKeySha256);

/// <summary>Wallet-side disclosure preview and post-consent signing for pinned did:web VC1.1 JWTs.</summary>
public static class JwtVcJsonPinnedDidWebWalletPreflight
{
    /// <summary>Only preview verified full claims after checking exact issuer and credential status.</summary>
    public static bool TryPrepare(
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid, TimeProvider clock,
        out JwtVcJsonPinnedDidWebWalletPreview? preview)
    {
        preview = null;
        throw new NotSupportedException("Wallet status preflight not implemented.");
    }

    /// <summary>After application-obtained consent, recheck the exact preview and sign with holder key.</summary>
    public static string CreateAfterPreview(
        JwtVcJsonPinnedDidWebWalletPreview preview,
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string statusJwt, byte[] independentlyPinnedIssuerPublicKey,
        byte[] holderSeed, TimeProvider clock) =>
        throw new NotSupportedException("Wallet post-consent signing not implemented.");
}
