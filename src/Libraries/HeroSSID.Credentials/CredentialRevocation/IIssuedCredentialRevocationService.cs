using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Credentials.CredentialRevocation;

/// <summary>
/// Revokes credentials this authenticated issuer tenant has actually issued.
/// This is a local issuer operation, not an interoperable published status-list API.
/// </summary>
public interface IIssuedCredentialRevocationService
{
    /// <summary>
    /// Atomically revokes active local records for an exact issued JWT.
    /// Returns false for unknown or other-tenant credentials, true for both first
    /// revocation and already-revoked credentials (idempotent).
    /// Caller authorization to exercise the revocation business scope is enforced by the API.
    /// </summary>
    Task<bool> RevokeAsync(
        ITenantContext issuerTenantContext,
        string credentialJwt,
        CancellationToken cancellationToken = default);
}
