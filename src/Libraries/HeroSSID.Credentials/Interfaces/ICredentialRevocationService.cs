namespace HeroSSID.Credentials.Interfaces;

/// <summary>
/// Service for checking credential revocation status
/// </summary>
/// <remarks>
/// PLACEHOLDER: This is a placeholder interface for MVP development.
/// Full revocation support will be implemented in a future release using
/// W3C Status List 2021 specification.
///
/// Future implementation will support:
/// - Bitstring-based status lists for efficient revocation checking
/// - Privacy-preserving status lookups
/// - Integration with credential issuance and verification
/// </remarks>
public interface ICredentialRevocationService
{
    /// <summary>
    /// Checks if a credential has been revoked
    /// </summary>
    /// <param name="credentialJwt">The credential JWT to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if credential is revoked, false if valid</returns>
    /// <exception cref="NotImplementedException">Thrown in MVP - revocation not yet implemented</exception>
    /// <remarks>
    /// PLACEHOLDER: Currently throws NotImplementedException.
    /// Future implementation will:
    /// 1. Extract status list URL from credential
    /// 2. Fetch and verify status list
    /// 3. Check credential's index in bitstring
    /// 4. Return revocation status
    /// </remarks>
    public Task<bool> CheckRevocationStatusAsync(
        string credentialJwt,
        CancellationToken cancellationToken = default);
}
