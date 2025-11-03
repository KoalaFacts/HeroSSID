using OpenIddict.EntityFrameworkCore.Models;

namespace HeroSSID.Data.Entities;

/// <summary>
/// Tenant-aware OpenIddict application entity with multi-tenant isolation.
/// </summary>
public class TenantAwareOpenIddictApplication : OpenIddictEntityFrameworkCoreApplication<Guid, TenantAwareOpenIddictAuthorization, TenantAwareOpenIddictToken>
{
    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;
}
