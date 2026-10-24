using HeroSSID.Core.TenantManagement;
using Microsoft.AspNetCore.Authorization;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Requires a signed client-credentials token with explicit issuance rights for the active tenant.
/// Tenant resolution itself is still single-tenant; this requirement prevents tokens belonging
/// to another tenant from being used to issue credentials under the MVP default tenant.
/// </summary>
internal sealed class CredentialIssueRequirement : IAuthorizationRequirement
{
    internal const string PolicyName = "RequireCredentialIssue";
}

internal sealed class CredentialIssueAuthorizationHandler(ITenantContext tenantContext)
    : AuthorizationHandler<CredentialIssueRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CredentialIssueRequirement requirement)
    {
        // Authentication/signature validation is performed by JwtBearer before this handler.
        // Require a dedicated scope claim (never a substring of another scope).
        if (context.User.Identity?.IsAuthenticated != true ||
            !context.User.HasClaim("scope", "credential:issue"))
        {
            return Task.CompletedTask;
        }

        // Reject absent, ambiguous, invalid or mismatched tenant claims. A trusted token
        // cannot authorize work on a different tenant just because the context is hardcoded.
        var tenantClaims = context.User.FindAll("tenant_id").ToArray();
        if (tenantClaims.Length != 1 ||
            !Guid.TryParse(tenantClaims[0].Value, out var tokenTenantId) ||
            tokenTenantId == Guid.Empty ||
            tokenTenantId != tenantContext.GetCurrentTenantId())
        {
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
