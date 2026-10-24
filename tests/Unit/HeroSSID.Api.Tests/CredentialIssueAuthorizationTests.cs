using System.Security.Claims;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using Microsoft.AspNetCore.Authorization;

namespace HeroSSID.Api.Tests;

public sealed class CredentialIssueAuthorizationTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Fact]
    public async Task AllowsExactIssueScopeAndMatchingTenant()
    {
        var principal = Principal(
            [new Claim("tenant_id", Tenant.ToString()), new Claim("scope", "credential:verify"),
             new Claim("scope", "credential:issue")]);
        Assert.True(await AllowedAsync(principal).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("credential:verify")]
    [InlineData("credential:issue:admin")]
    [InlineData("credential:issue credential:verify")]
    [InlineData("Credential:Issue")]
    public async Task RejectsOtherOrCombinedScopeValues(string scope)
    {
        Assert.False(await AllowedAsync(Principal(
            [new Claim("tenant_id", Tenant.ToString()), new Claim("scope", scope)])).ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectsMissingScope()
    {
        Assert.False(await AllowedAsync(Principal([new Claim("tenant_id", Tenant.ToString())])).ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectsOtherTenant()
    {
        Assert.False(await AllowedAsync(Principal(
            [new Claim("tenant_id", Guid.NewGuid().ToString()), new Claim("scope", "credential:issue")])).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task RejectsInvalidTenantId(string tenantId)
    {
        Assert.False(await AllowedAsync(Principal(
            [new Claim("tenant_id", tenantId), new Claim("scope", "credential:issue")])).ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectsAbsentTenant()
    {
        Assert.False(await AllowedAsync(Principal([new Claim("scope", "credential:issue")])).ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectsDuplicateTenantEvenWhenEqual()
    {
        Assert.False(await AllowedAsync(Principal(
            [new Claim("tenant_id", Tenant.ToString()), new Claim("tenant_id", Tenant.ToString()),
             new Claim("scope", "credential:issue")])).ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectsUnauthenticatedPrincipalWithValidClaims()
    {
        var principal = Principal(
            [new Claim("tenant_id", Tenant.ToString()), new Claim("scope", "credential:issue")],
            authenticated: false);
        Assert.False(await AllowedAsync(principal).ConfigureAwait(true));
    }

    private static ClaimsPrincipal Principal(IEnumerable<Claim> claims, bool authenticated = true) =>
        new(new ClaimsIdentity(claims, authenticated ? "test-jwt" : null));

    private static async Task<bool> AllowedAsync(ClaimsPrincipal principal)
    {
        var requirement = new CredentialIssueRequirement();
        var context = new AuthorizationHandlerContext([requirement], principal, resource: null);
        var handler = new CredentialIssueAuthorizationHandler(new TenantDouble());
        await handler.HandleAsync(context).ConfigureAwait(true);
        return context.HasSucceeded;
    }

    private sealed class TenantDouble : ITenantContext
    {
        public Guid GetCurrentTenantId() => Tenant;
    }
}
