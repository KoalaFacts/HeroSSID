using HeroSSID.Core.Interfaces;
using HeroSSID.Credentials.Models;

namespace HeroSSID.Credentials.Interfaces;

/// <summary>
/// Service for creating and verifying W3C Verifiable Presentations with selective disclosure
/// </summary>
/// <remarks>
/// Verifiable Presentations allow holders to:
/// 1. Combine multiple credentials into a single presentation
/// 2. Selectively disclose only required claims (privacy-preserving)
/// 3. Prove possession of credentials without revealing all data
///
/// Uses SD-JWT (Selective Disclosure for JWTs) per IETF draft-22.
/// </remarks>
public interface IVerifiablePresentationService
{
    /// <summary>
    /// Creates a Verifiable Presentation from a credential with selective disclosure
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation</param>
    /// <param name="credentialJwt">Original credential JWT-VC to present</param>
    /// <param name="claimsToDisclose">Specific claim names to disclose (null = disclose all)</param>
    /// <param name="holderDidId">Database ID of the holder's DID (presenter)</param>
    /// <param name="audience">Optional DID of the verifier (audience for the presentation)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Presentation result with VP-JWT and selected disclosures</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when credential or DID is invalid</exception>
    /// <remarks>
    /// The holder controls which claims to disclose via the claimsToDisclose parameter.
    /// Undisclosed claims remain hashed in the JWT (privacy-preserving).
    /// </remarks>
    public Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext,
        string credentialJwt,
        string[]? claimsToDisclose,
        Guid holderDidId,
        string? audience = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a Verifiable Presentation and validates selective disclosures
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation</param>
    /// <param name="presentationJwt">VP-JWT to verify</param>
    /// <param name="disclosureTokens">Disclosure tokens provided by holder</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Verification result with disclosed claims</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when presentationJwt is null or empty</exception>
    /// <remarks>
    /// Verifies:
    /// 1. VP-JWT signature (holder signed the presentation)
    /// 2. Embedded credential signatures (issuers signed credentials)
    /// 3. Disclosure tokens match hash digests in credentials
    /// 4. Credential expiration dates
    /// </remarks>
    public Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext tenantContext,
        string presentationJwt,
        string[] disclosureTokens,
        CancellationToken cancellationToken = default);
}
