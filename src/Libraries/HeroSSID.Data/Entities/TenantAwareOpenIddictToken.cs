using OpenIddict.EntityFrameworkCore.Models;

namespace HeroSSID.Data.Entities;

/// <summary>
/// Tenant-aware OpenIddict token entity with multi-tenant isolation.
/// </summary>
public class TenantAwareOpenIddictToken : OpenIddictEntityFrameworkCoreToken<Guid, TenantAwareOpenIddictApplication, TenantAwareOpenIddictAuthorization>
{
    /// <summary>
    /// Multi-tenant isolation identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;
}
