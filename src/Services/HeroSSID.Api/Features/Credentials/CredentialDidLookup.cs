using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Resolves REST DID identifiers to the IDs required by the issuance service.</summary>
internal interface ICredentialDidLookup
{
    public Task<Guid?> FindIssuerAsync(string did, Guid tenantId, CancellationToken cancellationToken);
    public Task<Guid?> FindHolderAsync(string did, CancellationToken cancellationToken);
}

internal sealed class CredentialDidLookup(HeroDbContext dbContext) : ICredentialDidLookup
{
    public Task<Guid?> FindIssuerAsync(string did, Guid tenantId, CancellationToken cancellationToken) =>
        dbContext.Dids.Where(entity => entity.DidIdentifier == did && entity.TenantId == tenantId)
            .Select(entity => (Guid?)entity.Id)
            .FirstOrDefaultAsync(cancellationToken);

    // The existing issuance service intentionally permits holders from another tenant.
    public Task<Guid?> FindHolderAsync(string did, CancellationToken cancellationToken) =>
        dbContext.Dids.Where(entity => entity.DidIdentifier == did)
            .Select(entity => (Guid?)entity.Id)
            .FirstOrDefaultAsync(cancellationToken);
}
