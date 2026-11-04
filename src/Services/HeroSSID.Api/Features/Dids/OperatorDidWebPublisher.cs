using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Api.Features.Dids;

/// <summary>
/// Opt-in, operator-configured public did:web document publisher.
/// Deliberately unavailable until its policy and HTTP contract are implemented.
/// </summary>
public sealed class OperatorDidWebPublisher
{
    public OperatorDidWebPublisher(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        throw new NotSupportedException("Operator-pinned did:web publishing is not implemented.");
    }

    public bool IsEnabled => throw new NotSupportedException();

    public string? Did => throw new NotSupportedException();

    public string? Document => throw new NotSupportedException();

    public IResult Handle(HttpContext context) => throw new NotSupportedException();

    public static void Map(IEndpointRouteBuilder app, OperatorDidWebPublisher publisher) =>
        throw new NotSupportedException();
}
