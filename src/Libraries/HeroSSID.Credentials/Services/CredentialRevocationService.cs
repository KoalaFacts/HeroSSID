using HeroSSID.Credentials.Interfaces;

namespace HeroSSID.Credentials.Services;

/// <summary>
/// Placeholder implementation of credential revocation checking
/// </summary>
/// <remarks>
/// PLACEHOLDER: This service currently throws NotImplementedException.
/// Full revocation support will be implemented in a future release using
/// W3C Status List 2021 (https://www.w3.org/TR/2023/WD-vc-status-list-20230427/).
///
/// Future implementation approach:
/// - Use bitstring-based status lists for efficient checking
/// - Support privacy-preserving lookups via HPKE
/// - Integrate with CredentialIssuanceService and CredentialVerificationService
/// - Database schema: CredentialStatusListEntity with compressed bitstrings
///
/// See revocation-future.md for detailed implementation plan.
/// </remarks>
public sealed class CredentialRevocationService : ICredentialRevocationService
{
    /// <summary>
    /// Checks if a credential has been revoked
    /// </summary>
    /// <param name="credentialJwt">The credential JWT to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if credential is revoked, false if valid</returns>
    /// <exception cref="NotImplementedException">Always thrown - revocation not yet implemented</exception>
    public Task<bool> CheckRevocationStatusAsync(
        string credentialJwt,
        CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException(
            "Credential revocation checking will be implemented in a future release. " +
            "The implementation will use W3C Status List 2021 specification for privacy-preserving revocation checks.");
    }
}
