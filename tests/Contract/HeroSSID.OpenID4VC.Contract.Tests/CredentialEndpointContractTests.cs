using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Contract tests for Credential endpoints - User Story 1
/// Tests the REST API contract for credential issuance and verification
/// </summary>
public class CredentialEndpointContractTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    /// <summary>
    /// T036: Contract test - POST /api/v1/credentials/issue returns JWT-VC with 201 status
    /// </summary>
    [Fact]
    public async Task PostCredentialsIssue_WithValidRequest_Returns201CreatedWithJwtVc()
    {
        // Arrange
        // First create issuer and holder DIDs
        var createIssuerDidRequest = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", createIssuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var createHolderDidRequest = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", createHolderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new
            {
                degree = new
                {
                    type = "BachelorDegree",
                    name = "Bachelor of Science in Computer Science"
                }
            }
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        // Verify response body structure
        var result = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(result);

        // JWT-VC should be returned
        var credential = result?.GetProperty("credential").GetString();
        Assert.NotNull(credential);

        // JWT format check (3 parts separated by dots)
        var parts = credential?.Split('.');
        Assert.Equal(3, parts?.Length);
    }

    /// <summary>
    /// T037: Contract test - POST /api/v1/credentials/verify returns verification result with 200 status
    /// </summary>
    [Fact]
    public async Task PostCredentialsVerify_WithValidCredential_Returns200OkWithVerificationResult()
    {
        // Arrange
        // First issue a credential
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new { degree = new { type = "BachelorDegree" } }
        };
        var issueResponse = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<dynamic>();
        string credential = issueResult?.GetProperty("credential").GetString()
            ?? throw new InvalidOperationException("Credential not found");

        var verifyRequest = new
        {
            Credential = credential
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Verify response structure
        var result = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(result);
        Assert.NotNull(result?.GetProperty("isValid"));
        Assert.NotNull(result?.GetProperty("issuerDid"));
        Assert.NotNull(result?.GetProperty("holderDid"));

        // Valid credential should return isValid: true
        bool isValid = result?.GetProperty("isValid").GetBoolean() ?? false;
        Assert.True(isValid);
    }

    [Fact]
    public async Task PostCredentialsIssue_WithInvalidIssuerDid_Returns400BadRequest()
    {
        // Arrange
        var issueRequest = new
        {
            IssuerDid = "did:key:invalid",
            HolderDid = "did:key:z6MkSomeValidKey",
            CredentialType = "UniversityDegreeCredential",
            Claims = new { }
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Verify RFC 9457 Problem Details
        var problemDetails = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(problemDetails);
        Assert.Equal(400, problemDetails?.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task PostCredentialsVerify_WithInvalidCredential_Returns400BadRequest()
    {
        // Arrange
        var verifyRequest = new
        {
            Credential = "invalid.jwt.token"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Verify RFC 9457 Problem Details
        var problemDetails = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(problemDetails);
        Assert.Equal(400, problemDetails?.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task PostCredentialsVerify_WithTamperedCredential_ReturnsInvalidResult()
    {
        // Arrange
        // First issue a valid credential
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new { degree = new { type = "BachelorDegree" } }
        };
        var issueResponse = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<dynamic>();
        string credential = issueResult?.GetProperty("credential").GetString()
            ?? throw new InvalidOperationException("Credential not found");

        // Tamper with the credential (change the signature)
        var parts = credential.Split('.');
        string tamperedCredential = $"{parts[0]}.{parts[1]}.TAMPERED";

        var verifyRequest = new
        {
            Credential = tamperedCredential
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Tampered credential should return isValid: false
        var result = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(result);
        bool isValid = result?.GetProperty("isValid").GetBoolean() ?? true;
        Assert.False(isValid);
    }

    /// <summary>
    /// T057: POST /api/v1/credentials/issue without token returns 401 Unauthorized
    /// User Story 4 - OAuth 2.0 Protection
    /// </summary>
    [Fact]
    public async Task PostCredentialsIssue_WithoutAuthorizationToken_Returns401()
    {
        // Arrange - create request without Authorization header
        // First create DIDs (DID creation should NOT require auth)
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new { degree = new { type = "BachelorDegree" } }
        };

        // Act - attempt to issue credential without Authorization header
        var response = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest);

        // Assert - should return 401 Unauthorized
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // Verify WWW-Authenticate header is present (OAuth requirement)
        Assert.True(response.Headers.Contains("WWW-Authenticate"), "WWW-Authenticate header must be present for 401 responses");
    }

    /// <summary>
    /// T058: POST /api/v1/credentials/issue with expired token returns 401
    /// User Story 4 - OAuth 2.0 Protection
    /// </summary>
    [Fact]
    public async Task PostCredentialsIssue_WithExpiredToken_Returns401()
    {
        // Arrange - create an expired token
        // This is a manual expired JWT for testing (iat and exp in the past)
        var expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X2NsaWVudCIsImlhdCI6MTYwOTQ1OTIwMCwiZXhwIjoxNjA5NDYyODAwfQ.invalid_signature";

        // Create DIDs
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new { degree = new { type = "BachelorDegree" } }
        };

        // Create HTTP request with expired token
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/credentials/issue")
        {
            Content = JsonContent.Create(issueRequest)
        };
        request.Headers.Add("Authorization", $"Bearer {expiredToken}");

        // Act
        var response = await _client.SendAsync(request);

        // Assert - should return 401 Unauthorized
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// T057: POST /api/v1/credentials/issue with valid token succeeds
    /// User Story 4 - OAuth 2.0 Protection (positive case)
    /// </summary>
    [Fact]
    public async Task PostCredentialsIssue_WithValidToken_Returns201()
    {
        // Arrange - obtain access token first
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = "credential:issue"
        });

        var tokenResponse = await _client.PostAsync("/oauth2/token", tokenRequest);
        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<dynamic>();
        string accessToken = tokenResult?.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Access token not found");

        // Create DIDs
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>();
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>();
        string holderDid = holderResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found");

        var issueRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new { degree = new { type = "BachelorDegree" } }
        };

        // Create HTTP request with access token
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/credentials/issue")
        {
            Content = JsonContent.Create(issueRequest)
        };
        request.Headers.Add("Authorization", $"Bearer {accessToken}");

        // Act
        var response = await _client.SendAsync(request);

        // Assert - should succeed with 201 Created
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var result = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(result);
        var credential = result?.GetProperty("credential").GetString();
        Assert.NotNull(credential);
    }
}
