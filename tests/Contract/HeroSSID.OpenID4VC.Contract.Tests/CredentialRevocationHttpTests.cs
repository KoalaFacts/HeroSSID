using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Live HTTP revocation contract backed by an isolated PostgreSQL Testcontainer.</summary>
#pragma warning disable CA1515 // Public test class discovered by xUnit.
public sealed class CredentialRevocationHttpTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
#pragma warning restore CA1515
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task IssuerCanRevokeStoredCredentialAndVerificationFailsClosed()
    {
        var setupToken = await GetTokenAsync("did:manage credential:issue credential:verify credential:revoke").ConfigureAwait(true);
        var issuer = await CreateDidAsync(setupToken).ConfigureAwait(true);
        var holder = await CreateDidAsync(setupToken).ConfigureAwait(true);
        using var issuedResponse = await PostAsync("/api/v1/credentials/issue",
            new { issuerDid = issuer, holderDid = holder, credentialType = "MembershipCredential", claims = new { member = true } },
            setupToken).ConfigureAwait(true);
        var credential = await SetupResponse.ReadRequiredStringAsync(
            issuedResponse, HttpStatusCode.Created, "Issue revocable credential", "credential").ConfigureAwait(true);

        using var initial = await PostAsync("/api/v1/credentials/verify", new { credential }, setupToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, initial.StatusCode);
        var before = await initial.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.True(before.GetProperty("isValid").GetBoolean());

        using var revoked = await PostAsync("/api/v1/credentials/revoke", new { credential }, setupToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using var repeated = await PostAsync("/api/v1/credentials/revoke", new { credential }, setupToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeated.StatusCode);

        using var verified = await PostAsync("/api/v1/credentials/verify", new { credential }, setupToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var after = await verified.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.False(after.GetProperty("isValid").GetBoolean());
        Assert.Equal(JsonValueKind.Null, after.GetProperty("issuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, after.GetProperty("holderDid").ValueKind);
    }

    [Fact]
    public async Task RevocationRequiresExplicitScopeAndDoesNotDiscloseUnknownCredentials()
    {
        using var anonymous = await _client.PostAsJsonAsync("/api/v1/credentials/revoke",
            new { credential = "unissued.jwt.token" }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        var issueOnly = await GetTokenAsync("credential:issue").ConfigureAwait(true);
        using var forbidden = await PostAsync("/api/v1/credentials/revoke",
            new { credential = "unissued.jwt.token" }, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var revokeOnly = await GetTokenAsync("credential:revoke").ConfigureAwait(true);
        using var missing = await PostAsync("/api/v1/credentials/revoke",
            new { credential = "unissued.jwt.token" }, revokeOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);

        using var invalid = await PostAsync("/api/v1/credentials/revoke",
            new { credential = " " }, revokeOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    private async Task<string> CreateDidAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Create revocation test DID", "did").ConfigureAwait(true);
    }

    private async Task<string> GetTokenAsync(string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await _client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.OK, "Obtain scoped token", "access_token").ConfigureAwait(true);
    }

    private async Task<HttpResponseMessage> PostAsync<T>(string uri, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(request).ConfigureAwait(true);
    }
}
