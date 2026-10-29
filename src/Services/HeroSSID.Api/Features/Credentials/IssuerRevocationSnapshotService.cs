using System.Security.Cryptography;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Opt-in issuer export of a signed, bounded, short-lived revocation snapshot.
/// Nothing is written to the database or published automatically.
/// </summary>
internal sealed class IssuerRevocationSnapshotService(
    HeroDbContext dbContext,
    IKeyEncryptionService encryption,
    IRateLimiter rateLimiter)
{
    internal const string RateLimitOperation = "REVOCATION_SNAPSHOT_EXPORT";
    internal const string LimitError = "Revocation snapshot has more entries than the supported complete export limit.";
    internal const string RateLimitError = "Rate limit exceeded for revocation snapshot export";

    internal async Task<string?> ExportAsync(
        ITenantContext context, string issuerDid, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerDid);
        var tenantId = context.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("An authenticated issuer tenant is required.", nameof(context));
        }

        if (!await rateLimiter.TryAcquireAsync(tenantId, RateLimitOperation, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(RateLimitError);
        }

        var issuer = await dbContext.Dids.AsNoTracking()
            .Where(did => did.TenantId == tenantId &&
                did.DidIdentifier == issuerDid && did.Status == "active")
            .Select(did => new { did.Id, did.PublicKeyEd25519, did.PrivateKeyEd25519Encrypted })
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        if (issuer is null)
        {
            return null;
        }

        // Only self-certifying, active did:key issuers may export proof. Historical
        // mismatched keys must never acquire a seemingly authoritative signature.
        try
        {
            if (!string.Equals(new DidKeyMethod().GenerateDidIdentifier(issuer.PublicKeyEd25519),
                issuerDid, StringComparison.Ordinal))
            {
                return null;
            }
        }
        catch (ArgumentException)
        {
            return null;
        }

        var revoked = await dbContext.VerifiableCredentials.AsNoTracking()
            .Where(item => item.TenantId == tenantId && item.IssuerDidId == issuer.Id && item.Status == "revoked")
            .OrderBy(item => item.Id)
            .Select(item => item.CredentialJwt)
            .Take(IssuerRevocationSnapshot.MaximumEntries + 1)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        if (revoked.Count > IssuerRevocationSnapshot.MaximumEntries)
        {
            // Never silently publish a partial "complete" revocation set.
            throw new InvalidOperationException(LimitError);
        }

        byte[]? privateKey = null;
        try
        {
            privateKey = encryption.Decrypt(issuer.PrivateKeyEd25519Encrypted);
            return IssuerRevocationSnapshot.Create(
                issuerDid, revoked, privateKey, issuer.PublicKeyEd25519, TimeProvider.System.GetUtcNow());
        }
        finally
        {
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }
}
