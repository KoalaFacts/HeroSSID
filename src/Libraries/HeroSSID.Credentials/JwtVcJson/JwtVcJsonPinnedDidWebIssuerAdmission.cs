using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Result of the combined, single-challenge did:web VC1.1 admission gate.</summary>
public enum JwtVcJsonPinnedDidWebIssuerAdmissionResult
{
    /// <summary>Invalid proof, issuer status, verifier policy or replay.</summary>
    Invalid,

    /// <summary>The verifier's separately managed exact-JWT policy denies disclosure.</summary>
    DeniedByVerifier,

    /// <summary>The actual issuer signed a fresh revoked status for this credential.</summary>
    RevokedByIssuer,

    /// <summary>Issuer and holder verified, local policy clean, issuer status signed not revoked.</summary>
    SignedNotRevoked
}

/// <summary>
/// SDK-only admission that must combine a local exact-credential denial list and
/// issuer-signed status on the same one-use holder proof before releasing claims.
/// This test-only contract intentionally throws until runtime RED is observed.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerAdmission
{
    /// <summary>
    /// Enforce both independent verifier denial policy and exact issuer-signed
    /// freshness with a single atomic verifier-owned challenge consumption.
    /// </summary>
    public static JwtVcJsonPinnedDidWebIssuerAdmissionResult Check(
        string presentationJwt, string statusJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Test-only RED: atomic did:web admission not yet implemented.");
    }
}
