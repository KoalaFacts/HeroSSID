using HeroSSID.Core.TenantManagement;
using HeroSSID.Api.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Requires a signed client-credentials token with explicit issuance rights for the active tenant.
/// Tenant resolution comes from the validated HTTP token; this requirement also guards
/// the active tenant boundary when authorization is invoked independently.
/// </summary>
internal sealed class CredentialIssueRequirement : IAuthorizationRequirement
{
    internal const string PolicyName = OperationScopes.CredentialIssue;
}

internal sealed class CredentialIssueAuthorizationHandler(ITenantContext tenantContext)
    : AuthorizationHandler<CredentialIssueRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CredentialIssueRequirement requirement)
    {
        // Authentication/signature validation is performed by JwtBearer before this handler.
        // Match an exact scope token, including repeated or space-delimited scope claims.
        if (context.User.Identity?.IsAuthenticated != true ||
            !OperationScopes.HasScope(context.User, OperationScopes.CredentialIssue))
        {
            return Task.CompletedTask;
        }

        // Keep scope authorization bound to the same tenant as the request context.
        if (!AuthenticatedTenantContext.TryGetTenantId(context.User, out var tokenTenantId) ||
            tokenTenantId != tenantContext.GetCurrentTenantId())
        {
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
