using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// T039: Integration test - Full flow: create issuer DID, holder DID, issue credential, verify credential
/// Tests end-to-end REST API workflow for User Story 1
/// </summary>
public class RestApiIntegrationTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task FullCredentialFlow_CreateDids_IssueCredential_VerifyCredential_AllSucceed()
    {
        var ct = TestContext.Current.CancellationToken;

        // Step 1: Create issuer DID
        var createIssuerDidRequest = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };

        var issuerDidResponse = await _client.PostAsJsonAsync("/api/v1/dids", createIssuerDidRequest, ct);
        Assert.Equal(HttpStatusCode.Created, issuerDidResponse.StatusCode);

        var issuerDidResult = await issuerDidResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
        Assert.NotNull(issuerDidResult);

        string issuerDid = issuerDidResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found in response");

        Assert.NotNull(issuerDid);
        Assert.StartsWith("did:key:", issuerDid);

        // Step 2: Create holder DID
        var createHolderDidRequest = new
        {
            Method = "did:key",
            KeyType = "Ed25519"
        };

        var holderDidResponse = await _client.PostAsJsonAsync("/api/v1/dids", createHolderDidRequest, ct);
        Assert.Equal(HttpStatusCode.Created, holderDidResponse.StatusCode);

        var holderDidResult = await holderDidResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
        Assert.NotNull(holderDidResult);

        string holderDid = holderDidResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Holder DID not found in response");

        Assert.NotNull(holderDid);
        Assert.StartsWith("did:key:", holderDid);

        // Step 3: Verify DIDs can be resolved
        var resolveIssuerResponse = await _client.GetAsync($"/api/v1/dids/{Uri.EscapeDataString(issuerDid)}", ct);
        Assert.Equal(HttpStatusCode.OK, resolveIssuerResponse.StatusCode);

        var issuerResponseContent = await resolveIssuerResponse.Content.ReadAsStringAsync(ct);
        var issuerDidDoc = System.Text.Json.JsonDocument.Parse(issuerResponseContent);
        var issuerRoot = issuerDidDoc.RootElement;
        Assert.True(issuerRoot.TryGetProperty("id", out var idElement), "DID document must have id property");
        Assert.Equal(issuerDid, idElement.GetString());

        var resolveHolderResponse = await _client.GetAsync($"/api/v1/dids/{Uri.EscapeDataString(holderDid)}", ct);
        Assert.Equal(HttpStatusCode.OK, resolveHolderResponse.StatusCode);

        // Step 4: Issue a verifiable credential
        var issueCredentialRequest = new
        {
            IssuerDid = issuerDid,
            HolderDid = holderDid,
            CredentialType = "UniversityDegreeCredential",
            Claims = new
            {
                degree = new
                {
                    type = "BachelorDegree",
                    name = "Bachelor of Science in Computer Science",
                    university = "Example University"
                },
                graduationDate = "2024-05-15"
            }
        };

        var issueResponse = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueCredentialRequest, ct);
        Assert.Equal(HttpStatusCode.Created, issueResponse.StatusCode);

        var issueResult = await issueResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
        Assert.NotNull(issueResult);

        string credential = issueResult?.GetProperty("credential").GetString()
            ?? throw new InvalidOperationException("Credential not found in response");

        Assert.NotNull(credential);

        // Verify JWT structure (header.payload.signature)
        var jwtParts = credential.Split('.');
        Assert.Equal(3, jwtParts.Length);

        // Step 5: Verify the credential
        var verifyRequest = new
        {
            Credential = credential
        };

        var verifyResponse = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest, ct);
        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);

        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
        Assert.NotNull(verifyResult);

        // Verify the credential is valid
        bool isValid = verifyResult?.GetProperty("isValid").GetBoolean() ?? false;
        Assert.True(isValid, "Credential should be valid");

        // Verify issuer and holder DIDs match
        string verifiedIssuerDid = verifyResult?.GetProperty("issuerDid").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found in verification result");
        string verifiedHolderDid = verifyResult?.GetProperty("holderDid").GetString()
            ?? throw new InvalidOperationException("Holder DID not found in verification result");

        Assert.Equal(issuerDid, verifiedIssuerDid);
        Assert.Equal(holderDid, verifiedHolderDid);

        // SUCCESS: Full workflow completed
        // - Created 2 DIDs
        // - Resolved both DIDs
        // - Issued a verifiable credential
        // - Verified the credential successfully
    }

    [Fact]
    public async Task FullFlow_WithMultipleCredentials_AllSucceed()
    {
        var ct = TestContext.Current.CancellationToken;

        // Create issuer DID once
        var issuerDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
        var issuerResponse = await _client.PostAsJsonAsync("/api/v1/dids", issuerDidRequest, ct);
        var issuerResult = await issuerResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
        string issuerDid = issuerResult?.GetProperty("did").GetString()
            ?? throw new InvalidOperationException("Issuer DID not found");

        // Issue multiple credentials to different holders
        var credentials = new List<string>();

        for (int i = 0; i < 3; i++)
        {
            // Create holder DID
            var holderDidRequest = new { Method = "did:key", KeyType = "Ed25519" };
            var holderResponse = await _client.PostAsJsonAsync("/api/v1/dids", holderDidRequest, ct);
            var holderResult = await holderResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
            string holderDid = holderResult?.GetProperty("did").GetString()
                ?? throw new InvalidOperationException($"Holder DID {i} not found");

            // Issue credential
            var issueRequest = new
            {
                IssuerDid = issuerDid,
                HolderDid = holderDid,
                CredentialType = "UniversityDegreeCredential",
                Claims = new { studentId = $"STU-{i:D3}", degree = "Computer Science" }
            };

            var issueResponse = await _client.PostAsJsonAsync("/api/v1/credentials/issue", issueRequest, ct);
            Assert.Equal(HttpStatusCode.Created, issueResponse.StatusCode);

            var issueResult = await issueResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
            string credential = issueResult?.GetProperty("credential").GetString()
                ?? throw new InvalidOperationException($"Credential {i} not found");

            credentials.Add(credential);
        }

        // Verify all credentials are valid
        foreach (var credential in credentials)
        {
            var verifyRequest = new { Credential = credential };
            var verifyResponse = await _client.PostAsJsonAsync("/api/v1/credentials/verify", verifyRequest, ct);

            Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);

            var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<dynamic>(cancellationToken: ct);
            bool isValid = verifyResult?.GetProperty("isValid").GetBoolean() ?? false;

            Assert.True(isValid, "All issued credentials should be valid");
        }
    }
}
