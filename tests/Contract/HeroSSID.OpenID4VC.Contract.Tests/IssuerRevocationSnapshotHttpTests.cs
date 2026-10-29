using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// True HTTP/PostgreSQL issuer snapshot export and offline Ed25519 verification.
/// This is an internal HeroSSID profile, not independent wallet interoperability.
/// </summary>
#pragma warning disable CA1515 // Public xUnit class is required for test discovery.
public sealed class IssuerRevocationSnapshotHttpTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
#pragma warning restore CA1515
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task IssuerExportsVerifiableRevocationBeforeAndAfterRevocation()
    {
        var token = await GetTokenAsync("did:manage credential:issue credential:revoke").ConfigureAwait(true);
        var issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        var holderDid = await CreateDidAsync(token).ConfigureAwait(true);
        var payload = new
        {
            issuerDid, holderDid, credentialType = "MembershipCredential",
            claims = new { membership = "current" }
        };
        using var issued = await PostAsync("/api/v1/credentials/issue", payload, token).ConfigureAwait(true);
        string credential = await SetupResponse.ReadRequiredStringAsync(
            issued, HttpStatusCode.Created, "Issue credential for offline status", "credential").ConfigureAwait(true);

        byte[] multicodec = SimpleBase.Base58.Bitcoin.Decode(issuerDid.AsSpan("did:key:z".Length));
        Assert.Equal(34, multicodec.Length);
        Assert.Equal(0xed, multicodec[0]);
        Assert.Equal(0x01, multicodec[1]);
        byte[] publicKey = multicodec[2..];

        using var beforeResponse = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid }, token).ConfigureAwait(true);
        string before = await SetupResponse.ReadRequiredStringAsync(
            beforeResponse, HttpStatusCode.OK, "Export before revocation", "snapshot").ConfigureAwait(true);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            IssuerRevocationSnapshot.Check(before, credential, issuerDid, publicKey, DateTimeOffset.UtcNow));

        using var revoked = await PostAsync("/api/v1/credentials/revoke",
            new { credential }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using var afterResponse = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid }, token).ConfigureAwait(true);
        string after = await SetupResponse.ReadRequiredStringAsync(
            afterResponse, HttpStatusCode.OK, "Export after revocation", "snapshot").ConfigureAwait(true);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            IssuerRevocationSnapshot.Check(after, credential, issuerDid, publicKey, DateTimeOffset.UtcNow));

        using var secondIssuer = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid = holderDid }, token).ConfigureAwait(true);
        string otherSnapshot = await SetupResponse.ReadRequiredStringAsync(
            secondIssuer, HttpStatusCode.OK, "Export unrelated issuer", "snapshot").ConfigureAwait(true);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(otherSnapshot, credential, issuerDid, publicKey, DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task SnapshotExportIsIssuerControlledAndRejectsInvalidRequests()
    {
        using var anonymous = await _client.PostAsJsonAsync(
            "/api/v1/credentials/revocation-snapshot", new { issuerDid = "did:key:zMissing" }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync("credential:verify").ConfigureAwait(true);
        using var forbidden = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid = "did:key:zMissing" }, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string revokeOnly = await GetTokenAsync("credential:revoke").ConfigureAwait(true);
        using var missing = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid = "did:key:zMissing" }, revokeOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);

        using var invalid = await PostAsync("/api/v1/credentials/revocation-snapshot",
            new { issuerDid = " " }, revokeOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    private async Task<string> CreateDidAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Create signing DID", "did").ConfigureAwait(true);
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
