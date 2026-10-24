using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Service for verifying W3C Verifiable Credentials
/// </summary>
public interface ICredentialVerificationService
{
    /// <summary>
    /// Verifies the cryptographic signature and validity of a JWT-VC credential
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation (REQUIRED for security)</param>
    /// <param name="credentialJwt">JWT-VC string to verify</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Structured verification result with status code and details</returns>
    /// <exception cref="ArgumentNullException">Thrown when tenantContext is null</exception>
    /// <exception cref="ArgumentException">Thrown when credentialJwt is null or empty</exception>
    /// <remarks>
    /// SECURITY: Tenant context is REQUIRED to ensure proper tenant isolation.
    /// Only DIDs belonging to the specified tenant will be used for verification.
    /// This prevents cross-tenant DID access and maintains security boundaries in multi-tenant deployments.
    /// </remarks>
    public Task<CredentialVerificationResult> VerifyCredentialAsync(
        ITenantContext tenantContext,
        string credentialJwt,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies an enrolled issuer's public credential while charging the actual requester.</summary>
    /// <param name="requesterContext">Trusted holder or verifier context responsible for the request.</param>
    /// <param name="issuerTenantId">Issuer lookup tenant resolved from its enrolled public DID record.</param>
    /// <param name="credentialJwt">Original issuer-signed JWT credential.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature and credential-state verification result.</returns>
    /// <remarks>
    /// This is public-record verification, not authorization to act for the issuer. Presentation callers
    /// must independently enforce their trusted issuer and holder policy. The issuer tenant scopes DID
    /// and revocation lookups only; the requester tenant owns the rate-limit charge. HTTP tenant-local
    /// verification must continue using <see cref="VerifyCredentialAsync"/>.
    /// </remarks>
    public Task<CredentialVerificationResult> VerifyCredentialFromIssuerAsync(
        ITenantContext requesterContext,
        Guid issuerTenantId,
        string credentialJwt,
        CancellationToken cancellationToken = default);
}
