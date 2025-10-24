using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Contract tests for Credential endpoints - User Story 1
/// Tests the REST API contract for credential issuance and verification
/// </summary>
public class CredentialEndpointContractTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
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
}
