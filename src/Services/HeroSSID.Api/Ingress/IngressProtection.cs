using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Api.Ingress;

/// <summary>Ingress partition and explicitly trusted proxy configuration.</summary>
internal static class IngressProtection
{
    internal static string PartitionKey(HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";

    internal static bool ConfigureForwarding(IServiceCollection services, IConfiguration configuration) =>
        false;
}
