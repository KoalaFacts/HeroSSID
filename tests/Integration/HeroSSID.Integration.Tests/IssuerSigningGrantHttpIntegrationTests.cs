using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Runs all three issuer-signing endpoints against actual authenticated HTTP,
/// tenant-owned Ed25519 signing keys and isolated PostgreSQL. Grant policy is
/// operator configuration, not a field trusted from the HTTP request.
/// </summary>
public sealed class IssuerSigningGrantHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture = fixture;
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");

    [Fact]
    public async Task EnforcedClientGrantBlocksOtherOwnedIssuerBeforeSigningOnAllRoutes()
    {
        await using (var db = _fixture.CreateDbContext<HeroDbContext>())
        {
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken)
                .ConfigureAwait(true);
        }

        // Create two separate active issuer DIDs with the SAME tenant and
        // credential:issue scope, then independently enroll only the first.
        await using var setupHost = new ConfiguredHost(_fixture.ConnectionString, null);
        using var setup = setupHost.CreateClient();
        string setupToken = await TokenAsync(setup).ConfigureAwait(true);
        string grantedDid = await CreateDidAsync(setup, setupToken).ConfigureAwait(true);
        string ungrantedDid = await CreateDidAsync(setup, setupToken).ConfigureAwait(true);
        string holderDid = await CreateDidAsync(setup, setupToken).ConfigureAwait(true);

        await using var enforcingHost = new ConfiguredHost(_fixture.ConnectionString, grantedDid);
        using var client = enforcingHost.CreateClient();
        string token = await TokenAsync(client).ConfigureAwait(true);

        static object Legacy(string issuer, string holder) => new
        {
            issuerDid = issuer, holderDid = holder,
            credentialType = "MembershipCredential",
            claims = new { membership = "active" }
        };
        object Vc11(string issuer) => new
        {
            issuerDid = issuer, holderDid,
            credentialType = "https://issuer.example/credentials#MembershipCredential",
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        };
        object Vc20(string issuer) => new
        {
            issuerDid = issuer, holderDid,
            credentialType = "MembershipCredential",
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        (string Path, object Denied, object Allowed)[] formats =
        [
            ("/api/v1/credentials/issue", Legacy(ungrantedDid, holderDid), Legacy(grantedDid, holderDid)),
            ("/api/v1/credentials/jwt-vc-json/issue", Vc11(ungrantedDid), Vc11(grantedDid)),
            ("/api/v1/credentials/vcdm20/issue", Vc20(ungrantedDid), Vc20(grantedDid))
        ];

        foreach (var format in formats)
        {
            using var denied = await PostAsync(client, format.Path, format.Denied, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);
        }

        await using (var db = _fixture.CreateDbContext<HeroDbContext>())
        {
            Assert.Equal(0, await db.VerifiableCredentials.CountAsync(
                TestContext.Current.CancellationToken).ConfigureAwait(true));
        }

        foreach (var format in formats)
        {
            using var allowed = await PostAsync(client, format.Path, format.Allowed, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
            var body = await allowed.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
            Assert.False(string.IsNullOrEmpty(body.GetProperty("credential").GetString()));
        }

        // Only the legacy format persists credentials; the VC1.1/VC2
        // short-lived issue routes explicitly do not claim stored revocation.
        await using (var db = _fixture.CreateDbContext<HeroDbContext>())
        {
            Assert.Equal(1, await db.VerifiableCredentials.CountAsync(
                TestContext.Current.CancellationToken).ConfigureAwait(true));
        }
    }

    private sealed class ConfiguredHost(string connection, string? grantedDid)
        : WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connection,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-issuer-client-signing-grants-secret-over-32-bytes"
                };
                if (grantedDid is not null)
                {
                    values["IssuerSigningGrants:EnforcedTenants:0"] =
                        HeroDbContext.DefaultTenantId.ToString("D");
                    values["IssuerSigningGrants:Grants:0:TenantId"] =
                        HeroDbContext.DefaultTenantId.ToString("D");
                    values["IssuerSigningGrants:Grants:0:ClientId"] = "test_client";
                    values["IssuerSigningGrants:Grants:0:IssuerDid"] = grantedDid;
                }

                configuration.AddInMemoryCollection(values);
            });
        }
    }

    private static async Task<string> TokenAsync(HttpClient client)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = "did:manage credential:issue"
        });
        using var result = await client.PostAsync("/oauth2/token", form,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        var json = await result.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        return json.GetProperty("access_token").GetString()!;
    }

    private static async Task<string> CreateDidAsync(HttpClient client, string token)
    {
        using var result = await PostAsync(client, "/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, result.StatusCode);
        var json = await result.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        return json.GetProperty("did").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
    }
}
