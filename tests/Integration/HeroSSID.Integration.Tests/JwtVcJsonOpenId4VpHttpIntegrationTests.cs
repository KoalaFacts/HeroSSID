using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Authenticated OpenID4VP 1.0 jwt_vc_json direct_post HTTP adapter, tested with
/// three distinct real Ed25519 signers and disposable PostgreSQL challenges.
/// This is not an independent wallet interoperability or human consent test.
/// </summary>
public sealed class JwtVcJsonOpenId4VpHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string IssueRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/signed-request";
    private const string VerifyRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/verify-response";
    private const string ResponseUri = "https://verifier.example/direct-post";
    private const string TypeIri = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task SignedRequestAndIndependentHolderResponseVerifyOnceWithIssuerStatus()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var issuedBody = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = issuedBody.GetProperty("signedRequestJwt").GetString()!;
        string nonce = issuedBody.GetProperty("nonce").GetString()!;
        Assert.Equal("decentralized_identifier:" + verifierDid,
            issuedBody.GetProperty("clientId").GetString());
        Assert.True(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, TimeProvider.System,
            out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(issuerDid, parsed.Challenge.TrustedIssuerDid);
        Assert.Equal(nonce, parsed.Challenge.Nonce);
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, holderDid, new Uri(ResponseUri), TypeIri, Context, TimeProvider.System, out _));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, verifierDid, new Uri("https://other.example/callback"), TypeIri,
            Context, TimeProvider.System, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string original = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string holderForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, original,
            holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System.GetUtcNow(),
            TimeProvider.System);
        var submitted = new
        {
            verifierDid, nonce, form = holderForm, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };
        using var verified = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var body = await verified.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", body.GetProperty("status").GetString());
        Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        var replayBody = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayBody.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task AuthenticRevokedIssuerCredentialNeverReleasesHolderClaims()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var details = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string nonce = details.GetProperty("nonce").GetString()!;
        string signedRequest = details.GetProperty("signedRequestJwt").GetString()!;

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "revoked-member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string holderForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signedRequest, verifierDid, new Uri(ResponseUri), TypeIri, Context,
            credential, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System);
        string revokedStatus = JwtVcJsonRevocationSnapshot.Create(issuerDid,
            [credential], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);

        var submitted = new
        {
            verifierDid, nonce, form = holderForm, revocationSnapshot = revokedStatus,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };
        using var denied = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedJson = await denied.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Revoked", deniedJson.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedJson.GetProperty("verifiedSubject").ValueKind);

        using var replay = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        var replayJson = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayJson.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayJson.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task NoBearerNoDualScopeForeignVerifierAndNonHttpsCallbackCannotIssue()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var unrelated = NewKey();
        string foreignDid = DidFromKey(unrelated);
        var request = new
        {
            verifierDid = foreignDid, responseUri = ResponseUri, trustedIssuerDid = foreignDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        };
        using var anonymous = await client.PostAsJsonAsync(IssueRoute, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        foreach (string scope in new[] { "credential:verify", "did:manage" })
        {
            string token = await GetTokenAsync(client, scope).ConfigureAwait(true);
            using var forbidden = await PostAsync(client, IssueRoute, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        string fullToken = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var foreign = await PostAsync(client, IssueRoute, request, fullToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        string ownedDid = await CreateDidAsync(client, fullToken).ConfigureAwait(true);
        using var insecure = await PostAsync(client, IssueRoute, new
        {
            verifierDid = ownedDid, responseUri = "http://verifier.example/direct-post",
            trustedIssuerDid = foreignDid, credentialType = TypeIri,
            subjectContextUri = Context.AbsoluteUri, lifetimeSeconds = 120
        }, fullToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, insecure.StatusCode);

        using var untrustedVerify = await client.PostAsJsonAsync(VerifyRoute, new
        {
            verifierDid = ownedDid, nonce = new string('A', 43), form = "state=a&vp_token=b",
            revocationSnapshot = "not-a-signed-snapshot", expectedCredentialType = TypeIri,
            subjectContextUri = Context.AbsoluteUri
        }, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, untrustedVerify.StatusCode);
    }

    private async Task EnsureMigratedAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest> NewHost() =>
        new ConfiguredHost(_fixture.ConnectionString);

    private sealed class ConfiguredHost(string connectionString)
        : WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-openid4vp-http-adapter-test-secret-with-at-least-32-bytes"
                }));
        }
    }

    private static async Task<string> CreateDidAsync(HttpClient client, string token)
    {
        using var response = await PostAsync(client, "/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await ReadStringAsync(response, HttpStatusCode.Created, "did").ConfigureAwait(true);
    }

    private static async Task<string> GetTokenAsync(HttpClient client, string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await ReadStringAsync(response, HttpStatusCode.OK, "access_token").ConfigureAwait(true);
    }

    private static async Task<string> ReadStringAsync(
        HttpResponseMessage response, HttpStatusCode expected, string name)
    {
        string content = await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(response.StatusCode == expected,
            $"Expected {expected} but received {response.StatusCode}: {content}");
        using var json = JsonDocument.Parse(content);
        return json.RootElement.GetProperty(name).GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string route, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
