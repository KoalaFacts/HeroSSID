using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Contract tests for OAuth 2.0 endpoints (User Story 4).
/// Tests client credentials grant flow per OAuth 2.0 specification.
/// </summary>
public sealed class OAuthEndpointContractTests : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client;

    public OAuthEndpointContractTests(AspireWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    /// <summary>
    /// T056: POST /oauth2/token with client_credentials returns access token
    /// </summary>
    [Fact]
    public async Task PostToken_WithClientCredentials_ReturnsAccessToken()
    {
        // Arrange - prepare client credentials grant request
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = "credential:issue credential:verify"
        });

        // Act - request access token
        var response = await _client.PostAsync("/oauth2/token", tokenRequest);

        // Assert - verify successful token response
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var tokenResponse = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Verify required OAuth 2.0 token response fields
        Assert.True(tokenResponse.TryGetProperty("access_token", out var accessToken), "access_token must be present");
        Assert.False(string.IsNullOrWhiteSpace(accessToken.GetString()), "access_token must not be empty");

        Assert.True(tokenResponse.TryGetProperty("token_type", out var tokenType), "token_type must be present");
        string tokenTypeValue = tokenType.GetString() ?? "";
        Assert.Equal("Bearer", tokenTypeValue, StringComparer.OrdinalIgnoreCase);

        Assert.True(tokenResponse.TryGetProperty("expires_in", out var expiresIn), "expires_in must be present");
        Assert.True(expiresIn.GetInt32() > 0, "expires_in must be positive");

        // Scope should be returned (optional but recommended)
        if (tokenResponse.TryGetProperty("scope", out var scope))
        {
            string scopeValue = scope.GetString() ?? "";
            Assert.Contains("credential:issue", scopeValue, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// T056: POST /oauth2/token with invalid credentials returns 401
    /// </summary>
    [Fact]
    public async Task PostToken_WithInvalidCredentials_Returns401()
    {
        // Arrange - invalid client credentials
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "invalid_client",
            ["client_secret"] = "wrong_secret"
        });

        // Act
        var response = await _client.PostAsync("/oauth2/token", tokenRequest);

        // Assert - should return 401 Unauthorized or 400 Bad Request per OAuth spec
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected 401 or 400, got {response.StatusCode}"
        );

        // Verify OAuth error response format
        var errorResponse = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.True(errorResponse.TryGetProperty("error", out var error), "error field must be present");
        string errorValue = error.GetString() ?? "";
        Assert.Contains("invalid", errorValue, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// T056: POST /oauth2/token with missing grant_type returns 400
    /// </summary>
    [Fact]
    public async Task PostToken_WithMissingGrantType_Returns400()
    {
        // Arrange - missing grant_type
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret"
        });

        // Act
        var response = await _client.PostAsync("/oauth2/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var errorResponse = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(errorResponse.TryGetProperty("error", out var error), "error field must be present");
        Assert.Equal("invalid_request", error.GetString());
    }

    /// <summary>
    /// T056: POST /oauth2/token with unsupported grant type returns 400
    /// </summary>
    [Fact]
    public async Task PostToken_WithUnsupportedGrantType_Returns400()
    {
        // Arrange - unsupported grant type
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password", // Not supported
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["username"] = "user",
            ["password"] = "pass"
        });

        // Act
        var response = await _client.PostAsync("/oauth2/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var errorResponse = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(errorResponse.TryGetProperty("error", out var error), "error field must be present");
        Assert.Equal("unsupported_grant_type", error.GetString());
    }
}
