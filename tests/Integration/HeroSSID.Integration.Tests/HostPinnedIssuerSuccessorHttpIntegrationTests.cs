using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Exercises verifier-operator-owned successor pins over two HTTP hosts and
/// a real, isolated PostgreSQL one-use challenge store. No production enrollment.
/// </summary>
public sealed class HostPinnedIssuerSuccessorHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string IssueRoute = "/api/v1/credentials/issuer-successor/host-pinned-challenge";
    private const string VerifyRoute = "/api/v1/credentials/issuer-successor/host-pinned-verify";
    private const string Audience = "https://verifier.example/host-pinned-successor";
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task GenuineUnapprovedSuccessorCannotConsumePreapprovedSuccessorsChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        using var attacker = NewKey();
        string oldDid = DidFromKey(previous);
        string approvedDid = DidFromKey(approved);
        await using var host = NewHost(oldDid, approvedDid);
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        string nonce = await IssueNonceAsync(client, token).ConfigureAwait(true);

        string wrong = Proof(previous, attacker, nonce);
        using var rejected = await PostAsync(client, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation = wrong }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        var invalid = await BodyAsync(rejected).ConfigureAwait(true);
        Assert.Equal("Invalid", invalid.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, invalid.GetProperty("successorIssuerDid").ValueKind);

        string correct = Proof(previous, approved, nonce);
        using var accepted = await PostAsync(client, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation = correct }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var success = await BodyAsync(accepted).ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity", success.GetProperty("status").GetString());
        Assert.Equal(approvedDid, success.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(client, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation = correct }, token).ConfigureAwait(true);
        Assert.Equal("Invalid", (await BodyAsync(replay).ConfigureAwait(true))
            .GetProperty("status").GetString());
    }

    [Fact]
    public async Task DifferentHttpReplicasConsumeExactlyOnePinnedChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        string oldDid = DidFromKey(previous);
        string approvedDid = DidFromKey(approved);
        await using var firstHost = NewHost(oldDid, approvedDid);
        await using var secondHost = NewHost(oldDid, approvedDid);
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);
        string nonce = await IssueNonceAsync(first, token).ConfigureAwait(true);
        string attestation = Proof(previous, approved, nonce);

        using var accepted = await PostAsync(second, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(accepted).ConfigureAwait(true)).GetProperty("status").GetString());

        using var replay = await PostAsync(first, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation }, token).ConfigureAwait(true);
        Assert.Equal("Invalid",
            (await BodyAsync(replay).ConfigureAwait(true)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task HostPolicyCannotBeInventedByAuthenticatedHttpCaller()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        string oldDid = DidFromKey(previous);
        string approvedDid = DidFromKey(approved);
        await using var pinned = NewHost(oldDid, approvedDid);
        await using var unpinned = NewHost(oldDid, approvedDid, configurePin: false);
        using var first = pinned.CreateClient();
        using var second = unpinned.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);

        using var missingPolicy = await PostAsync(second, IssueRoute,
            new { policyId = "issuer-migration", lifetimeSeconds = 120 }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, missingPolicy.StatusCode);

        string nonce = await IssueNonceAsync(first, token).ConfigureAwait(true);
        string attestation = Proof(previous, approved, nonce);
        using var unpinnedVerification = await PostAsync(second, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation,
                expectedSuccessorIssuerDid = approvedDid }, token).ConfigureAwait(true);
        // A caller must not be able to turn an undeclared verifier pin into trust.
        Assert.NotEqual(HttpStatusCode.OK, unpinnedVerification.StatusCode);

        using var accepted = await PostAsync(first, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation }, token).ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(accepted).ConfigureAwait(true)).GetProperty("status").GetString());
    }

    private async Task EnsureMigratedAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private ConfiguredHost NewHost(string oldDid, string successorDid, bool configurePin = true) =>
        new(_fixture.ConnectionString, oldDid, successorDid, configurePin);

    private sealed class ConfiguredHost(string connectionString, string oldDid,
        string successorDid, bool configurePin)
        : WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, config) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-host-pinned-issuer-successor-test-secret-over-32-bytes"
                };
                if (configurePin)
                {
                    const string prefix = "IssuerSuccessorTrust:Policies:0:";
                    values[prefix + "TenantId"] = HeroDbContext.DefaultTenantId.ToString("D");
                    values[prefix + "PolicyId"] = "issuer-migration";
                    values[prefix + "Audience"] = Audience;
                    values[prefix + "TrustedPreviousIssuerDid"] = oldDid;
                    values[prefix + "PreapprovedSuccessorIssuerDid"] = successorDid;
                }

                config.AddInMemoryCollection(values);
            });
        }
    }

    private static async Task<string> IssueNonceAsync(HttpClient client, string token)
    {
        using var response = await PostAsync(client, IssueRoute,
            new { policyId = "issuer-migration", lifetimeSeconds = 120 }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await BodyAsync(response).ConfigureAwait(true);
        Assert.Equal(Audience, body.GetProperty("audience").GetString());
        return body.GetProperty("nonce").GetString()!;
    }

    private static string Proof(Key previous, Key successor, string nonce) =>
        IssuerKeySuccessorAttestation.Create(DidFromKey(previous), DidFromKey(successor),
            previous.Export(KeyBlobFormat.RawPrivateKey),
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Uri(Audience), nonce, TimeProvider.System);

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

    private static async Task<string> GetTokenAsync(HttpClient client, string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await client.PostAsync("/oauth2/token", form,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await BodyAsync(response).ConfigureAwait(true))
            .GetProperty("access_token").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
