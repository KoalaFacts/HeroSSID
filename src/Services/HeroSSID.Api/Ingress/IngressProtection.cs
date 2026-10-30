using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Api.Ingress;

/// <summary>
/// Derives bounded request budgets from validated client identities or the actual
/// network peer. Forwarded addresses are considered only when explicitly trusted.
/// </summary>
internal static class IngressProtection
{
    internal static string PartitionKey(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.User.Identity?.IsAuthenticated == true)
        {
            var tenants = context.User.FindAll("tenant_id").ToArray();
            if (tenants.Length == 1 &&
                Guid.TryParse(tenants[0].Value, out var tenantId) &&
                tenantId != Guid.Empty)
            {
                // Authentication validates the signed tenant claim before this
                // middleware. Never use Name, token text or a request header as
                // the key: those are absent or trivially changed for OAuth clients.
                var clients = context.User.FindAll("client_id").ToArray();
                if (clients.Length == 1 &&
                    !string.IsNullOrWhiteSpace(clients[0].Value) &&
                    clients[0].Value.Length <= 256)
                {
                    return "tenant:" + tenantId.ToString("D") + ":client:" + clients[0].Value;
                }

                // Unusual but validated tokens without a stable client_id still
                // share a finite tenant budget, never a per-token budget.
                return "tenant:" + tenantId.ToString("D");
            }
        }

        // This address may be rewritten ONLY by ForwardedHeadersMiddleware,
        // whose trusted proxy list is explicit and whose ForwardLimit is one.
        var address = context.Connection.RemoteIpAddress;
        if (address?.IsIPv4MappedToIPv6 == true)
        {
            address = address.MapToIPv4();
        }

        return "ip:" + (address?.ToString() ?? "unknown");
    }

    internal static bool ConfigureForwarding(IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        if (!configuration.GetValue<bool>("Ingress:ForwardedHeaders:Enabled"))
        {
            return false;
        }

        var configuredProxies = configuration.GetSection("Ingress:ForwardedHeaders:KnownProxies")
            .Get<string[]>() ?? [];
        var configuredNetworks = configuration.GetSection("Ingress:ForwardedHeaders:KnownNetworks")
            .Get<string[]>() ?? [];

        if (configuredProxies.Length + configuredNetworks.Length == 0)
        {
            throw new InvalidOperationException(
                "Ingress forwarded headers require explicitly trusted KnownProxies or KnownNetworks.");
        }

        var proxies = new List<IPAddress>(configuredProxies.Length);
        foreach (string value in configuredProxies)
        {
            if (!IPAddress.TryParse(value, out var proxy) ||
                IPAddress.Any.Equals(proxy) || IPAddress.IPv6Any.Equals(proxy))
            {
                throw new InvalidOperationException(
                    "Ingress:ForwardedHeaders:KnownProxies contains an invalid or wildcard address.");
            }

            proxies.Add(proxy);
        }

        var networks = new List<System.Net.IPNetwork>(configuredNetworks.Length);
        foreach (string value in configuredNetworks)
        {
            if (!System.Net.IPNetwork.TryParse(value, out var network) ||
                network.PrefixLength == 0)
            {
                throw new InvalidOperationException(
                    "Ingress:ForwardedHeaders:KnownNetworks requires bounded CIDR networks.");
            }

            networks.Add(network);
        }

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.RequireHeaderSymmetry = true;
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (var proxy in proxies)
            {
                options.KnownProxies.Add(proxy);
            }

            foreach (var network in networks)
            {
                options.KnownIPNetworks.Add(network);
            }
        });
        return true;
    }

    internal static void AddRateLimiting(
        IServiceCollection services, int perSourcePermitLimit = 100, int aggregatePermitLimit = 10_000)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(perSourcePermitLimit);
        if (aggregatePermitLimit < perSourcePermitLimit)
        {
            throw new ArgumentOutOfRangeException(
                nameof(aggregatePermitLimit), "The aggregate budget must not be below the source budget.");
        }

        services.AddRateLimiter(options =>
        {
            // Each validated tenant/client or anonymous remote peer has a
            // separate fixed-window budget. A second process-wide ceiling
            // bounds abuse through many changing client identities or IPs.
            options.GlobalLimiter = PartitionedRateLimiter.CreateChained(
                PartitionedRateLimiter.Create<HttpContext, string>(context =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        PartitionKey(context), _ => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = perSourcePermitLimit,
                            QueueLimit = 0,
                            Window = TimeSpan.FromMinutes(1)
                        })),
                PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        "all-http-requests", __ => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = aggregatePermitLimit,
                            QueueLimit = 0,
                            Window = TimeSpan.FromMinutes(1)
                        })));

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });
    }
}
