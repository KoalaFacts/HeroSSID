using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Contract tests for .well-known endpoints - User Story 4
/// Tests OAuth 2.0 authorization server metadata endpoint
/// </summary>
public sealed class WellKnownEndpointContractTests : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client;

    public WellKnownEndpointContractTests(AspireWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    /// <summary>
    /// T059: GET /.well-known/oauth-authorization-server returns valid OAuth metadata
    /// Per RFC 8414 - OAuth 2.0 Authorization Server Metadata
    /// </summary>
    [Fact]
    public async Task GetWellKnownOAuthAuthorizationServer_ReturnsValidMetadata()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");

        // Assert - verify successful response
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Verify Content-Type is application/json
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        // Parse and validate metadata
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();

        // RFC 8414 REQUIRED fields
        Assert.True(metadata.TryGetProperty("issuer", out var issuer), "issuer MUST be present");
        string issuerValue = issuer.GetString() ?? "";
        Assert.False(string.IsNullOrWhiteSpace(issuerValue), "issuer must not be empty");
        // Accept both HTTP (test) and HTTPS (production)
        Assert.True(
            issuerValue.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            issuerValue.StartsWith("http://", StringComparison.OrdinalIgnoreCase),
            "issuer must be a valid HTTP or HTTPS URL");

        Assert.True(metadata.TryGetProperty("token_endpoint", out var tokenEndpoint), "token_endpoint MUST be present");
        string tokenEndpointValue = tokenEndpoint.GetString() ?? "";
        Assert.False(string.IsNullOrWhiteSpace(tokenEndpointValue), "token_endpoint must not be empty");
        Assert.Contains("/oauth2/token", tokenEndpointValue, StringComparison.OrdinalIgnoreCase);

        // RFC 8414 RECOMMENDED fields
        Assert.True(metadata.TryGetProperty("grant_types_supported", out var grantTypes), "grant_types_supported SHOULD be present");
        var grantTypesArray = grantTypes.EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("client_credentials", grantTypesArray);

        Assert.True(metadata.TryGetProperty("token_endpoint_auth_methods_supported", out var authMethods), "token_endpoint_auth_methods_supported SHOULD be present");
        var authMethodsArray = authMethods.EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("client_secret_post", authMethodsArray);

        // Scopes supported (application-specific)
        if (metadata.TryGetProperty("scopes_supported", out var scopes))
        {
            var scopesArray = scopes.EnumerateArray().Select(x => x.GetString()).ToList();
            Assert.Contains("credential:issue", scopesArray);
            Assert.Contains("credential:verify", scopesArray);
        }
    }

    /// <summary>
    /// T059: Verify OAuth metadata issuer matches the server URL
    /// </summary>
    [Fact]
    public async Task GetWellKnownOAuthAuthorizationServer_IssuerMatchesServerUrl()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Assert - issuer should match the server's base URL
        Assert.True(metadata.TryGetProperty("issuer", out var issuer));
        var issuerUrl = issuer.GetString();
        Assert.NotNull(issuerUrl);

        // The issuer should be a valid HTTP or HTTPS URL
        Assert.True(Uri.TryCreate(issuerUrl, UriKind.Absolute, out var issuerUri), "issuer must be a valid absolute URL");
        Assert.True(
            issuerUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            issuerUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
            "issuer scheme must be HTTP or HTTPS");
    }

    /// <summary>
    /// T059: Verify all OAuth metadata endpoints are absolute URLs
    /// </summary>
    [Fact]
    public async Task GetWellKnownOAuthAuthorizationServer_EndpointsAreAbsoluteUrls()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Assert - all endpoint URLs should be absolute
        var endpointProperties = new[] { "token_endpoint", "issuer" };

        foreach (var prop in endpointProperties)
        {
            if (metadata.TryGetProperty(prop, out var endpoint))
            {
                var endpointUrl = endpoint.GetString();
                Assert.NotNull(endpointUrl);
                Assert.True(
                    Uri.TryCreate(endpointUrl, UriKind.Absolute, out var uri),
                    $"{prop} must be an absolute URL, got: {endpointUrl}"
                );
                Assert.True(
                    uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
                    uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
                    $"{prop} scheme must be HTTP or HTTPS");
            }
        }
    }

    /// <summary>
    /// T059: Verify OAuth metadata supports required grant types for HeroSSID
    /// </summary>
    [Fact]
    public async Task GetWellKnownOAuthAuthorizationServer_SupportsRequiredGrantTypes()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Assert - verify HeroSSID required grant types
        Assert.True(metadata.TryGetProperty("grant_types_supported", out var grantTypes));
        var grantTypesArray = grantTypes.EnumerateArray().Select(x => x.GetString()).ToList();

        // Client credentials grant is REQUIRED for credential issuance API
        Assert.Contains("client_credentials", grantTypesArray);

        // Pre-authorized code grant will be added in User Story 2 (OpenID4VCI)
        // We don't assert it here as it's not part of US4
    }
}
