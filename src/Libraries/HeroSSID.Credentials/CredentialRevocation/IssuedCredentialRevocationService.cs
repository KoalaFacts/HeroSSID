using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Credentials.CredentialRevocation;

/// <summary>
/// Local, persisted issuer revocation. Uses a database-side conditional update so
/// separate API instances cannot silently overwrite the first revocation timestamp.
/// </summary>
public sealed class IssuedCredentialRevocationService(
    HeroDbContext dbContext,
    IRateLimiter rateLimiter,
    TimeProvider? timeProvider = null) : IIssuedCredentialRevocationService
{
    private const int MaxCredentialLength = 1_000_000;
    private const string RateLimitOperation = "CREDENTIAL_REVOKE";

    public async Task<bool> RevokeAsync(
        ITenantContext issuerTenantContext,
        string credentialJwt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuerTenantContext);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(rateLimiter);
        if (string.IsNullOrWhiteSpace(credentialJwt) || credentialJwt.Length > MaxCredentialLength)
        {
            throw new ArgumentException("A bounded, non-empty credential JWT is required.", nameof(credentialJwt));
        }

        var tenantId = issuerTenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("An authenticated issuer tenant is required.", nameof(issuerTenantContext));
        }

        if (!await rateLimiter.TryAcquireAsync(tenantId, RateLimitOperation, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Rate limit exceeded for credential revocation");
        }

        // Exact persisted JWT equality prevents an arbitrary holder from revoking an
        // unissued token. Both recorded tenant ownership and the real issuer DID
        // owner must match the authenticated actor; no JWT-provided DID is trusted.
        var owned = dbContext.VerifiableCredentials
            .Where(credential => credential.TenantId == tenantId &&
                credential.CredentialJwt == credentialJwt &&
                dbContext.Dids.Any(did => did.Id == credential.IssuerDidId && did.TenantId == tenantId));

        var now = (timeProvider ?? TimeProvider.System).GetUtcNow();
        // Database-side update is atomic across processes and only transitions active
        // rows. Repeated requests preserve the original RevokedAt and UpdatedAt values.
        var changed = await owned.Where(credential => credential.Status == "active")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(credential => credential.Status, "revoked")
                .SetProperty(credential => credential.RevokedAt, (DateTimeOffset?)now)
                .SetProperty(credential => credential.UpdatedAt, now),
                cancellationToken).ConfigureAwait(false);

        return changed > 0 || await owned.AnyAsync(
            credential => credential.Status == "revoked", cancellationToken).ConfigureAwait(false);
    }
}
