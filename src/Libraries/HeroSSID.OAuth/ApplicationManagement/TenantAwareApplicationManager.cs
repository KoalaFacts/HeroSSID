using HeroSSID.Core.TenantManagement;
using HeroSSID.Data.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;

namespace HeroSSID.OAuth.ApplicationManagement;

/// <summary>
/// Tenant-aware OpenIddict application manager that filters applications by tenant.
/// Feature: Application Management
/// </summary>
public class TenantAwareApplicationManager : OpenIddictApplicationManager<TenantAwareOpenIddictApplication>
{
    private readonly ITenantContext _tenantContext;

    public TenantAwareApplicationManager(
        IOpenIddictApplicationCache<TenantAwareOpenIddictApplication> cache,
        ILogger<TenantAwareApplicationManager> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictApplicationStoreResolver resolver,
        ITenantContext tenantContext)
        : base(cache, logger, options, resolver)
    {
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
    }

    /// <summary>
    /// Finds an application by client ID, filtered by current tenant (CRITICAL-5).
    /// </summary>
    public override async ValueTask<TenantAwareOpenIddictApplication?> FindByClientIdAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        var application = await base.FindByClientIdAsync(identifier, cancellationToken).ConfigureAwait(false);

        if (application is null)
        {
            return null;
        }

        // Multi-tenant isolation: Verify the application belongs to the current tenant
        var currentTenantId = _tenantContext.GetCurrentTenantId().ToString();
        if (application.TenantId != currentTenantId)
        {
            // Return null instead of throwing to prevent tenant enumeration attacks
            return null;
        }

        return application;
    }
}
