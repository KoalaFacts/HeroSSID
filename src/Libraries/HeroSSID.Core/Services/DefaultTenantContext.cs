using HeroSSID.Core.Interfaces;

namespace HeroSSID.Core.Services;

/// <summary>
/// Default tenant context for MVP single-tenant deployment.
/// Returns the hardcoded default tenant ID.
///
/// FUTURE: Replace with proper multi-tenant context that extracts tenant from:
/// - HTTP headers (X-Tenant-Id)
/// - JWT claims
/// - Database lookup from authenticated user
/// - Azure AD tenant ID
/// </summary>
public sealed class DefaultTenantContext : ITenantContext
{
    // Hardcoded default tenant ID for MVP
    // This matches the value in HeroDbContext.DefaultTenantId
    private static readonly Guid s_defaultTenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    /// <inheritdoc />
    public Guid GetCurrentTenantId()
    {
        // For MVP, always return the default tenant
        // v2: Replace with actual tenant resolution logic
        return s_defaultTenantId;
    }
}
