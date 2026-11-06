using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Opt-in exact-credential issuer-signed status for a separately pinned did:web issuer.
/// This private status envelope is not a W3C status-list or interoperability profile.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerStatus
{
    /// <summary>
    /// Sign one issuer-observed revoked/not-revoked statement over the original compact VC JWT.
    /// The caller independently owns issuer key custody and the authoritative status record.
    /// </summary>
    public static string Create(
        string originalCredentialJwt, string issuerDid, string assertionMethodId,
        byte[] independentlyPinnedIssuerPublicKey, byte[] issuerSeed,
        bool revoked, DateTimeOffset observedAt, TimeProvider clock)
    {
        throw new NotSupportedException("Runtime RED: did:web issuer exact-JWT status issuance is not implemented.");
    }

    /// <summary>
    /// Authenticate the original issuer/holder signatures and one-use verifier challenge,
    /// then gate disclosure on a fresh genuine issuer status for that exact credential.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckPresentation(
        string presentationJwt, string statusJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        throw new NotSupportedException("Runtime RED: did:web issuer-signed status presentation verification is not implemented.");
    }
}
