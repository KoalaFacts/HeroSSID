using System.Net;
using System.Net.Http;
using System.Security.Claims;
using HeroSSID.Api.Ingress;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;

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

    [Fact]
    public async Task TrustedProxySeparatesActualClientsAndPreservesForwardedHttps()
    {
        using var server = NewServer(trustProxy: true);
        using var client = server.CreateClient();

        var first = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https").ConfigureAwait(true);
        var second = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https").ConfigureAwait(true);
        var exhausted = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https").ConfigureAwait(true);
        var independent = await ProbeAsync(client, "192.0.2.15", "198.51.100.11", "https").ConfigureAwait(true);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal("198.51.100.10|https", first.Body);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.Status);
        Assert.Equal(HttpStatusCode.OK, independent.Status);
        Assert.Equal("198.51.100.11|https", independent.Body);
    }

    [Fact]
    public async Task UntrustedPeerCannotSpoofForwardedAddressOrHttps()
    {
        using var server = NewServer(trustProxy: true);
        using var client = server.CreateClient();

        var first = await ProbeAsync(client, "203.0.113.40", "198.51.100.10", "https").ConfigureAwait(true);
        var second = await ProbeAsync(client, "203.0.113.40", "198.51.100.11", "https").ConfigureAwait(true);
        var spoofed = await ProbeAsync(client, "203.0.113.40", "198.51.100.12", "https").ConfigureAwait(true);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal("203.0.113.40|http", first.Body);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(HttpStatusCode.TooManyRequests, spoofed.Status);
    }

    [Fact]
    public async Task DirectPeersUseRealAddressesEvenWithSpoofedHeaders()
    {
        using var server = NewServer(trustProxy: false);
        using var client = server.CreateClient();

        var first = await ProbeAsync(client, "203.0.113.40", "198.51.100.10", "https").ConfigureAwait(true);
        var second = await ProbeAsync(client, "203.0.113.40", "198.51.100.11", "https").ConfigureAwait(true);
        var exhausted = await ProbeAsync(client, "203.0.113.40", "198.51.100.12", "https").ConfigureAwait(true);
        var independent = await ProbeAsync(client, "203.0.113.41").ConfigureAwait(true);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal("203.0.113.40|http", first.Body);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.Status);
        Assert.Equal(HttpStatusCode.OK, independent.Status);
    }

    [Fact]
    public async Task TwoValidatedClientsRemainIndependentBehindSharedAddress()
    {
        using var server = NewServer(trustProxy: true);
        using var client = server.CreateClient();

        var first = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https", "alice").ConfigureAwait(true);
        var second = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https", "alice").ConfigureAwait(true);
        var exhausted = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https", "alice").ConfigureAwait(true);
        var other = await ProbeAsync(client, "192.0.2.15", "198.51.100.10", "https", "bob").ConfigureAwait(true);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.Status);
        Assert.Equal(HttpStatusCode.OK, other.Status);
    }

    [Fact]
    public async Task ProcessWideBudgetStillBlocksChangingClientIdentifiers()
    {
        using var server = NewServer(trustProxy: false, aggregatePermitLimit: 3);
        using var client = server.CreateClient();

        Assert.Equal(HttpStatusCode.OK,
            (await ProbeAsync(client, "203.0.113.40", clientId: "alice").ConfigureAwait(true)).Status);
        Assert.Equal(HttpStatusCode.OK,
            (await ProbeAsync(client, "203.0.113.40", clientId: "alice").ConfigureAwait(true)).Status);
        Assert.Equal(HttpStatusCode.OK,
            (await ProbeAsync(client, "203.0.113.40", clientId: "bob").ConfigureAwait(true)).Status);
        Assert.Equal(HttpStatusCode.TooManyRequests,
            (await ProbeAsync(client, "203.0.113.40", clientId: "charlie").ConfigureAwait(true)).Status);
    }

    private static TestServer NewServer(bool trustProxy, int aggregatePermitLimit = 32)
    {
        var configuration = Configuration(
            ("Ingress:ForwardedHeaders:Enabled", trustProxy.ToString()),
            ("Ingress:ForwardedHeaders:KnownProxies:0", "192.0.2.15"));

        return new TestServer(new WebHostBuilder()
            .ConfigureServices(services =>
            {
                IngressProtection.ConfigureForwarding(services, configuration);
                IngressProtection.AddRateLimiting(
                    services, perSourcePermitLimit: 2, aggregatePermitLimit: aggregatePermitLimit);
            })
            .Configure(app =>
            {
                // TestServer does not carry a real TCP peer. This test-only
                // middleware simulates the CONNECTING PEER, not forwarded headers.
                app.Use((context, next) =>
                {
                    context.Connection.RemoteIpAddress =
                        IPAddress.Parse(context.Request.Headers["X-Test-Peer"].ToString());
                    return next(context);
                });

                if (trustProxy)
                {
                    app.UseForwardedHeaders();
                }

                // Simulate already-validated bearer claims in an isolated host.
                // Production obtains these claims from its JWT verification.
                app.Use((context, next) =>
                {
                    string id = context.Request.Headers["X-Test-Client"].ToString();
                    if (id.Length != 0)
                    {
                        context.User = new ClaimsPrincipal(new ClaimsIdentity(
                            [
                                new Claim("tenant_id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                                new Claim("client_id", id)
                            ], "validated"));
                    }

                    return next(context);
                });
                app.UseRateLimiter();
                app.Run(context => context.Response.WriteAsync(
                    context.Connection.RemoteIpAddress + "|" + context.Request.Scheme));
            }));
    }

    private static async Task<(HttpStatusCode Status, string Body)> ProbeAsync(
        HttpClient client, string peer, string? forwardedFor = null,
        string? forwardedProto = null, string? clientId = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/probe");
        request.Headers.Add("X-Test-Peer", peer);
        if (forwardedFor is not null)
        {
            request.Headers.Add("X-Forwarded-For", forwardedFor);
        }
        if (forwardedProto is not null)
        {
            request.Headers.Add("X-Forwarded-Proto", forwardedProto);
        }
        if (clientId is not null)
        {
            request.Headers.Add("X-Test-Client", clientId);
        }

        using var response = await client.SendAsync(
            request, TestContext.Current.CancellationToken).ConfigureAwait(true);
        return (response.StatusCode,
            await response.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken).ConfigureAwait(true));
    }
}
