using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Creates and verifies issuer-preserving, full-disclosure JWT presentations.</summary>
/// <remarks>This closed-system development profile is not SD-JWT or an OpenID4VP protocol implementation.</remarks>
public interface IVerifiablePresentationService
{
    /// <summary>Issues a single-use challenge with verifier-owned audience and issuer policy.</summary>
    public PresentationChallenge CreateChallenge(ITenantContext verifierContext, string audience, string trustedIssuerDid, TimeSpan? lifetime = null);

    /// <summary>Validates and embeds the entire original credential in a holder-signed, challenge-bound proof.</summary>
    public Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext, string credentialJwt, Guid holderDidId,
        PresentationChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>Verifies both signatures, holder binding, state and lifetime; atomically consumes a successful challenge.</summary>
    public Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext verifierContext, string presentationJwt, string expectedAudience,
        string expectedNonce, CancellationToken cancellationToken = default);

    /// <summary>Legacy challenge-less API. Always rejects; use the explicit full-disclosure overload.</summary>
    public Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext, string credentialJwt, string[]? claimsToDisclose,
        Guid holderDidId, string? audience = null, CancellationToken cancellationToken = default);

    /// <summary>Legacy challenge-less API. Always returns an invalid result.</summary>
    public Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext tenantContext, string presentationJwt, string[] disclosureTokens,
        CancellationToken cancellationToken = default);
}
