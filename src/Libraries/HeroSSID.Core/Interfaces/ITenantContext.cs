namespace HeroSSID.Core.Interfaces;

/// <summary>
/// Provides access to the current tenant context for multi-tenant isolation.
/// SECURITY: Proper tenant isolation prevents cross-tenant data access.
/// </summary>
public interface ITenantContext
{
    /// <summary>
    /// Gets the current tenant ID for the active request/session.
    /// SECURITY: This must be securely validated and cannot be user-controlled.
    /// </summary>
    /// <returns>The tenant ID (GUID)</returns>
    public Guid GetCurrentTenantId();
}
