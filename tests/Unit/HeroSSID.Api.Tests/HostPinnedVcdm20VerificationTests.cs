using HeroSSID.Api.Features.Credentials;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace HeroSSID.Api.Tests;

public sealed class HostPinnedVcdm20VerificationTests
{
    [Fact]
    public async Task AuthenticatedHostPinnedIssuerVerificationRouteIsAvailable()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing"
        });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();

        RouteEndpoint[] routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints)
            .OfType<RouteEndpoint>().ToArray();

        var route = Assert.Single(routes,
            endpoint => endpoint.RoutePattern.RawText ==
                "/api/v1/credentials/vcdm20/verify-host-pinned");
        Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            static policy => policy.Policy == "credential:verify");
        Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal("POST", Assert.Single(route.Metadata
            .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
    }
}
