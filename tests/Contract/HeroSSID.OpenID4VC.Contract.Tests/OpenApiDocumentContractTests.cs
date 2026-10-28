using System.Net;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Keeps development OpenAPI consumers on the same document version when the runtime changes.
/// The API's wire-level credential and OAuth contracts must not silently change for SDK generators.
/// </summary>
public sealed class OpenApiDocumentContractTests : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client;

    public OpenApiDocumentContractTests(AspireWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task DevelopmentOpenApiDocument_PreservesOpenApi30ForExistingConsumers()
    {
        using var response = await _client.GetAsync("/openapi/v1.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var document = await JsonDocument.ParseAsync(stream);

        var version = document.RootElement.GetProperty("openapi").GetString();
        Assert.NotNull(version);
        Assert.StartsWith("3.0.", version);
    }
}
