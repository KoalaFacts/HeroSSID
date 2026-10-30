using System.Net;
using System.Security.Claims;
using HeroSSID.Api.Ingress;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.HttpOverrides;

namespace HeroSSID.Api.Tests;

public sealed class IngressProtectionTests
{
    [Fact]
    public void TwoValidatedClientsBehindOneProxyHaveIndependentPartitions()
    {
        var tenant = Guid.NewGuid();
        var alice = RequestContext(IPAddress.Parse("192.0.2.15"), tenant, "alice");
        var bob = RequestContext(IPAddress.Parse("192.0.2.15"), tenant, "bob");
        Assert.NotEqual(IngressProtection.PartitionKey(alice), IngressProtection.PartitionKey(bob));
    }

    [Fact]
    public void DifferentValidatedTenantsCannotShareAClientPartition()
    {
        var alice = RequestContext(IPAddress.Parse("192.0.2.15"), Guid.NewGuid(), "shared");
        var bob = RequestContext(IPAddress.Parse("192.0.2.15"), Guid.NewGuid(), "shared");
        Assert.NotEqual(IngressProtection.PartitionKey(alice), IngressProtection.PartitionKey(bob));
    }

    [Fact]
    public void AnonymousCallerCannotChoosePartitionUsingUnsignedClaims()
    {
        var alice = RequestContext(IPAddress.Parse("198.51.100.23"), null, "alice");
        var bob = RequestContext(IPAddress.Parse("198.51.100.23"), null, "bob");
        Assert.Equal(IngressProtection.PartitionKey(alice), IngressProtection.PartitionKey(bob));
    }

    [Fact]
    public void AnonymousDifferentRemoteAddressesAreSeparateAndDirect()
    {
        var alice = RequestContext(IPAddress.Parse("198.51.100.23"), null, null);
        var bob = RequestContext(IPAddress.Parse("198.51.100.24"), null, null);
        Assert.NotEqual(IngressProtection.PartitionKey(alice), IngressProtection.PartitionKey(bob));
    }

    [Fact]
    public void EnabledForwardingRejectsMissingTrustedProxyConfiguration()
    {
        var config = Configuration(("Ingress:ForwardedHeaders:Enabled", "true"));
        Assert.Throws<InvalidOperationException>(() =>
            IngressProtection.ConfigureForwarding(new ServiceCollection(), config));
    }

    [Fact]
    public void EnabledForwardingPinsOnlyTheExplicitlyTrustedProxy()
    {
        var config = Configuration(
            ("Ingress:ForwardedHeaders:Enabled", "true"),
            ("Ingress:ForwardedHeaders:KnownProxies:0", "192.0.2.15"));
        var services = new ServiceCollection();
        Assert.True(IngressProtection.ConfigureForwarding(services, config));
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        Assert.Contains(IPAddress.Parse("192.0.2.15"), options.KnownProxies);
        Assert.DoesNotContain(IPAddress.Any, options.KnownProxies);
    }

    private static DefaultHttpContext RequestContext(IPAddress address, Guid? tenant, string? client)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = address;
        var claims = new List<Claim>();
        if (tenant is Guid id)
        {
            claims.Add(new Claim("tenant_id", id.ToString("D")));
        }
        if (client is not null)
        {
            claims.Add(new Claim("client_id", client));
        }
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, tenant is null ? null : "validated"));
        return context;
    }

    private static IConfiguration Configuration(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.ToDictionary(item => item.Key, item => (string?)item.Value))
            .Build();
}
