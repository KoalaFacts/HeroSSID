using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Infrastructure.TenantManagement;

/// <summary>
/// Default tenant context for MVP single-tenant deployment.
/// Returns the hardcoded default tenant ID.
/// </summary>
/// <remarks>
/// ⚠️ **WARNING: NOT PRODUCTION-READY FOR MULTI-TENANT SCENARIOS** ⚠️
///
/// This implementation is suitable ONLY for:
/// - MVP/prototype deployments
/// - Development and testing environments
/// - Single-tenant installations
///
/// **CRITICAL LIMITATIONS:**
/// - Always returns the same hardcoded tenant ID (11111111-1111-1111-1111-111111111111)
/// - No actual tenant isolation - all users share the same tenant
/// - Cannot support multiple tenants or organizations
/// - No authentication/authorization integration
///
/// **BEFORE PRODUCTION DEPLOYMENT:**
/// Replace this with a proper multi-tenant context implementation that extracts tenant ID from:
/// - HTTP request headers (e.g., X-Tenant-Id)
/// - JWT token claims (e.g., "tenant_id" claim)
/// - Database lookup based on authenticated user
/// - Azure AD tenant ID
/// - OAuth2 client credentials
///
/// Example production implementation:
/// <code>
/// public class ProductionTenantContext : ITenantContext
/// {
///     private readonly IHttpContextAccessor _httpContextAccessor;
///
///     public Guid GetCurrentTenantId()
///     {
///         // Extract from JWT claim
///         var tenantClaim = _httpContextAccessor.HttpContext?.User.FindFirst("tenant_id");
///         if (tenantClaim == null)
///             throw new UnauthorizedAccessException("No tenant context found");
///
///         return Guid.Parse(tenantClaim.Value);
///     }
/// }
/// </code>
/// </remarks>
public sealed class DefaultTenantContext : ITenantContext
{
    // ⚠️ HARDCODED DEFAULT TENANT ID - NOT PRODUCTION-READY ⚠️
    // This matches the value in HeroDbContext.DefaultTenantId
    // Replace with actual tenant resolution before production deployment
    private static readonly Guid _defaultTenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    /// <inheritdoc />
    public Guid GetCurrentTenantId()
    {
        // For MVP, always return the default tenant
        // v2: Replace with actual tenant resolution logic
        return _defaultTenantId;
    }
}
