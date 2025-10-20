using HeroSSID.Core.Interfaces;
using HeroSSID.Credentials.Models;

namespace HeroSSID.Credentials.Interfaces;

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
}
