using System.Text.Json;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Authenticated full-disclosure preview for a wallet application. The digest
/// identifies the exact signed request and original issuer credential to show
/// before later holder signing; it is not evidence of human consent.
/// </summary>
public sealed record JwtVcJsonWalletDisclosurePreview(
    string VerifierDid,
    Uri ResponseUri,
    string TrustedIssuerDid,
    string HolderDid,
    string CredentialType,
    Uri SubjectContextUri,
    DateTimeOffset RequestExpiresAt,
    JsonElement VerifiedSubject,
    string RequestSha256,
    string CredentialSha256);

/// <summary>
/// Wallet preflight for the bounded OpenID4VP jwt_vc_json direct_post profile.
/// This API never signs or consumes a challenge, nor does it obtain consent.
/// </summary>
public static class OpenId4VpJwtVcJsonWalletDisclosure
{
    /// <summary>
    /// Independently verify a pinned request and the original issuer JWT, and
    /// expose the entire signed subject to a wallet UI before asking permission.
    /// No holder private key is required for preview.
    /// </summary>
    public static bool TryPrepare(
        string requestJwt, string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        string expectedIssuerDid, string credentialJwt, string holderDid,
        TimeProvider clock, out JwtVcJsonWalletDisclosurePreview? preview)
    {
        preview = null;
        return false;
    }

    /// <summary>
    /// After the integrating application has obtained actual informed consent,
    /// revalidate the exact request and issuer credential shown in the preview
    /// before signing the holder's full-disclosure VP.
    /// </summary>
    public static string CreateHolderResponseFormAfterPreview(
        JwtVcJsonWalletDisclosurePreview preview,
        string requestJwt, string credentialJwt, byte[] holderSeed,
        TimeProvider clock)
    {
        throw new NotSupportedException("Wallet disclosure preflight is not implemented.");
    }
}
