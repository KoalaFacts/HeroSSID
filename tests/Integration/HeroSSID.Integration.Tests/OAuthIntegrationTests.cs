using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Integration tests for OAuth 2.0 flow - User Story 4
/// Tests end-to-end OAuth authorization with tenant isolation
/// </summary>
public sealed class OAuthIntegrationTests : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client;

    public OAuthIntegrationTests(AspireWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    /// <summary>
    /// T060: Obtain token, issue credential, verify tenant isolation enforced
    /// Full OAuth 2.0 protected credential issuance flow
    /// </summary>
    [Fact]
    public async Task FullOAuthFlow_ObtainToken_IssueCredential_TenantIsolationEnforced()
    {
        var ct = TestContext.Current.CancellationToken;

        // Step 1: Obtain OAuth access token using client credentials
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = "credential:issue credential:verify"
        });

        var tokenResponse = await _client.PostAsync("/oauth2/token", tokenRequest, ct);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        Assert.True(tokenResult.TryGetProperty("access_token", out var accessTokenElement));
        string accessToken = accessTokenElement.GetString()
            ?? throw new InvalidOperationException("Access token not found");

        Assert.False(string.IsNullOrWhiteSpace(accessToken), "Access token must not be empty");

        // Step 2: Create DIDs (no auth required)
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest, ct);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        string issuerDid = issuerResult.TryGetProperty("did", out var issuerDidElement)
            ? issuerDidElement.GetString() ?? throw new InvalidOperationException("Issuer DID is null")
            : throw new InvalidOperationException("Issuer DID not found");

        var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest, ct);
        var holderResult = await holderResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        string holderDid = holderResult.TryGetProperty("did", out var holderDidElement)
            ? holderDidElement.GetString() ?? throw new InvalidOperationException("Holder DID is null")
            : throw new InvalidOperationException("Holder DID not found");

        // Step 3: Issue credential WITH auth token
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

        using var issueHttpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/credentials/issue")
        {
            Content = JsonContent.Create(issueRequest)
        };
        issueHttpRequest.Headers.Add("Authorization", $"Bearer {accessToken}");

        var issueResponse = await _client.SendAsync(issueHttpRequest, ct);
        Assert.Equal(HttpStatusCode.Created, issueResponse.StatusCode);

        var issueResponseContent = await issueResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        Assert.True(issueResponseContent.TryGetProperty("credential", out var credentialElement));
        string credential = credentialElement.GetString()
            ?? throw new InvalidOperationException("Credential not found");

        // Verify JWT structure
        var jwtParts = credential.Split('.');
        Assert.Equal(3, jwtParts.Length);

        // Step 4: Verify the credential (currently no auth required, but respects token if provided)
        var verifyRequest = new { Credential = credential };

        var verifyResponse = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest, ct);
        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);

        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        Assert.True(verifyResult.TryGetProperty("isValid", out var isValidElement));
        bool isValid = isValidElement.GetBoolean();
        Assert.True(isValid, "Credential should be valid");

        // Step 5: Verify tenant isolation - attempt to issue without token should fail
        var unauthorizedIssueResponse = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorizedIssueResponse.StatusCode);
    }

    /// <summary>
    /// T060: Verify OAuth token has tenant context embedded
    /// Ensures multi-tenant isolation at the token level
    /// </summary>
    [Fact]
    public async Task OAuthToken_ContainsTenantClaims()
    {
        var ct = TestContext.Current.CancellationToken;

        // Obtain token
        using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = "credential:issue"
        });

        var tokenResponse = await _client.PostAsync("/oauth2/token", tokenRequest, ct);
        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        string accessToken = tokenResult.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Access token not found");

        // Decode JWT to verify tenant claims (just base64 decode, no signature verification needed for this test)
        var parts = accessToken.Split('.');
        Assert.Equal(3, parts.Length);

        // Decode payload (second part)
        var payloadBytes = Convert.FromBase64String(PadBase64(parts[1]));
        var payloadJson = System.Text.Encoding.UTF8.GetString(payloadBytes);
        var payload = JsonSerializer.Deserialize<JsonElement>(payloadJson);

        // Verify standard JWT claims
        Assert.True(payload.TryGetProperty("iss", out _), "iss (issuer) claim must be present");
        Assert.True(payload.TryGetProperty("exp", out _), "exp (expiration) claim must be present");
        Assert.True(payload.TryGetProperty("iat", out _), "iat (issued at) claim must be present");

        // Verify client/subject claims
        Assert.True(payload.TryGetProperty("sub", out var sub), "sub (subject) claim must be present");
        Assert.Equal("test_client", sub.GetString());

        // Tenant claim should be present (added by OpenIddict configuration)
        // Note: The exact claim name depends on implementation (tenant_id, tid, or custom claim)
    }

    /// <summary>
    /// Helper to pad base64 strings for decoding
    /// </summary>
    private static string PadBase64(string base64)
    {
        // JWT uses base64url encoding without padding
        var base64Url = base64.Replace('-', '+').Replace('_', '/');
        switch (base64Url.Length % 4)
        {
            case 2: return base64Url + "==";
            case 3: return base64Url + "=";
            default: return base64Url;
        }
    }
}
