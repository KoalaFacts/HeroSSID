using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Contract tests for DID endpoints - User Story 1
/// Tests the REST API contract for DID creation and resolution
/// </summary>
public class DidEndpointContractTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    /// <summary>
    /// T034: Contract test - POST /api/v1/dids creates DID with 201 status
    /// </summary>
    [Fact]
    public async Task PostDids_CreatesDidWithValidRequest_Returns201Created()
    {
        // Arrange
        var request = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/dids", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        // Verify response headers
        Assert.NotNull(response.Headers.Location);

        // Verify response body structure
        var result = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(result);
        // Additional assertions will be added when DTOs are implemented
    }

    /// <summary>
    /// T035: Contract test - GET /api/v1/dids/{did} resolves DID with 200 status and W3C DID Document
    /// </summary>
    [Fact]
    public async Task GetDids_WithValidDid_Returns200OkWithDidDocument()
    {
        // Arrange
        // First create a DID
        var createRequest = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };
        var createResponse = await _client.PostAsJsonAsync("/api/v1/dids", createRequest);
        var createResult = await createResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        // Extract DID from response (location or body)
        string did = createResult.TryGetProperty("did", out var didElement)
            ? didElement.GetString() ?? throw new InvalidOperationException("DID value is null")
            : throw new InvalidOperationException("DID not found in create response");

        // Act
        var response = await _client.GetAsync($"/api/v1/dids/{Uri.EscapeDataString(did)}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Verify response is a valid W3C DID Document
        var responseContent = await response.Content.ReadAsStringAsync();

        // Parse the JSON response
        var didDocument = System.Text.Json.JsonDocument.Parse(responseContent);
        var root = didDocument.RootElement;

        // W3C DID Document MUST have these properties
        Assert.Equal(System.Text.Json.JsonValueKind.Object, root.ValueKind);  // Ensure root is an object, not a string
        Assert.True(root.TryGetProperty("@context", out _), "@context property must exist");
        Assert.True(root.TryGetProperty("id", out _), "id property must exist");
        Assert.True(root.TryGetProperty("verificationMethod", out _), "verificationMethod property must exist");
    }

    /// <summary>
    /// T038: Contract test - Invalid DID creation returns 400 with RFC 9457 Problem Details
    /// </summary>
    [Fact]
    public async Task PostDids_WithInvalidRequest_Returns400BadRequest()
    {
        // Arrange
        var invalidRequest = new
        {
            // Missing required fields
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/dids", invalidRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Verify RFC 9457 Problem Details response
        var problemDetails = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(problemDetails);
        Assert.NotNull(problemDetails?.GetProperty("type"));
        Assert.NotNull(problemDetails?.GetProperty("title"));
        Assert.NotNull(problemDetails?.GetProperty("status"));
        Assert.Equal(400, problemDetails?.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task GetDids_WithNonExistentDid_Returns404NotFound()
    {
        // Arrange
        string nonExistentDid = "did:key:z6MkNonExistent";

        // Act
        var response = await _client.GetAsync($"/api/v1/dids/{Uri.EscapeDataString(nonExistentDid)}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        // Verify RFC 9457 Problem Details response
        var problemDetails = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(problemDetails);
        Assert.Equal(404, problemDetails?.GetProperty("status").GetInt32());
    }
}
