using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Credentials.CredentialIssuance;

/// <summary>
/// Service for issuing W3C Verifiable Credentials in JWT-VC format
/// </summary>
public interface ICredentialIssuanceService
{
    /// <summary>
    /// Issues a new W3C Verifiable Credential as a JWT-VC
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation</param>
    /// <param name="issuerDidId">Database ID of the issuer DID</param>
    /// <param name="holderDidId">Database ID of the holder DID (credential subject)</param>
    /// <param name="credentialType">Type of credential (e.g., "UniversityDegreeCredential")</param>
    /// <param name="credentialSubject">Claims to include in the credential</param>
    /// <param name="expirationDate">Optional expiration date (null = no expiration)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>JWT-VC string in compact serialization format</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when issuerDidId or holderDidId not found or inactive</exception>
    /// <exception cref="InvalidOperationException">Thrown when DID key decryption fails</exception>
    public Task<string> IssueCredentialAsync(
        ITenantContext tenantContext,
        Guid issuerDidId,
        Guid holderDidId,
        string credentialType,
        Dictionary<string, object> credentialSubject,
        DateTimeOffset? expirationDate = null,
        CancellationToken cancellationToken = default);
}
