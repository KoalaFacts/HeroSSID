using OpenIddict.EntityFrameworkCore.Models;

namespace HeroSSID.Data.Entities;

/// <summary>
/// Tenant-aware OpenIddict authorization entity with multi-tenant isolation.
/// </summary>
public class TenantAwareOpenIddictAuthorization : OpenIddictEntityFrameworkCoreAuthorization<Guid, TenantAwareOpenIddictApplication, TenantAwareOpenIddictToken>
{
    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;
}
