using OpenIddict.EntityFrameworkCore.Models;

namespace HeroSSID.Data.Entities;

/// <summary>
/// Tenant-aware OpenIddict scope entity with multi-tenant isolation.
/// </summary>
public class TenantAwareOpenIddictScope : OpenIddictEntityFrameworkCoreScope<Guid>
{
    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;
}
