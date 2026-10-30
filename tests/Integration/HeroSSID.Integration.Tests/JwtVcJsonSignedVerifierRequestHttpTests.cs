using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
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
/// Two independently hosted HTTP verifiers and real holder/issuer Ed25519 keys
/// exercise the complete VC1.1 signed-request boundary against disposable PostgreSQL.
/// This is not third-party wallet conformance or a human consent demonstration.
/// </summary>
public sealed class JwtVcJsonSignedVerifierRequestHttpTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string Route = "/api/v1/credentials/jwt-vc-json/signed-presentation-request";
    private const string VerifyRoute = "/api/v1/credentials/jwt-vc-json/verify-presentation";
    private const string Audience = "https://verifier.example/receive";
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task IssuedSignedRequestAuthenticatesVerifierAndHolderProofIsAcceptedOnceAcrossHosts()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(first, token).ConfigureAwait(true);
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = DidFromKey(issuer);
        string holderDid = DidFromKey(holder);

        using var issue = await PostAsync(first, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issue.StatusCode);
        var issued = await issue.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        string signed = issued.GetProperty("signedRequestJwt").GetString()!;
        Assert.Equal(verifierDid, issued.GetProperty("verifierDid").GetString());
        Assert.Equal(Audience, issued.GetProperty("audience").GetString());
        Assert.Equal(issuerDid, issued.GetProperty("trustedIssuerDid").GetString());
        Assert.True(OfflineSignedPresentationRequest.TryRead(signed,
            verifierDid, Audience, TimeProvider.System, out var challenge));
        Assert.NotNull(challenge);
        Assert.Equal(issued.GetProperty("nonce").GetString(), challenge.Nonce);
        Assert.False(OfflineSignedPresentationRequest.TryRead(signed,
            holderDid, Audience, TimeProvider.System, out _));
        Assert.False(OfflineSignedPresentationRequest.TryRead(signed,
            verifierDid, "https://other.example/receive", TimeProvider.System, out _));
        string[] parts = signed.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(signed)
            .Replace(Audience, "https://evil.example/receive", StringComparison.Ordinal));
        Assert.False(OfflineSignedPresentationRequest.TryRead(string.Join('.', parts),
            verifierDid, Audience, TimeProvider.System, out _));

        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid,
            CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(5));
        // The holder application is still responsible for showing all claims and obtaining
        // affirmative consent; the library only checks independent pinned verifier proof.
        string presentation = JwtVcJsonPresentation.Create(signed,
            verifierDid, Audience, credential, CredentialType, Vocabulary,
            holderDid, holder.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuer.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        var verifyRequest = new
        {
            presentation, revocationSnapshot = status, audience = Audience,
            nonce = challenge.Nonce, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary.AbsoluteUri
        };
        string verifyToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var accepted = await PostAsync(second, VerifyRoute, verifyRequest, verifyToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var acceptedBody = await accepted.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", acceptedBody.GetProperty("status").GetString());
        Assert.Equal("member", acceptedBody.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await PostAsync(first, VerifyRoute, verifyRequest, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var replayBody = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayBody.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task SignerRequiresBothScopesAndActiveTenantOwnedDid()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var external = NewKey();
        string foreignDid = DidFromKey(external);
        var request = new
        {
            verifierDid = foreignDid, audience = Audience,
            trustedIssuerDid = foreignDid, lifetimeSeconds = 120
        };
        using var anonymous = await client.PostAsJsonAsync(Route, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifierOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var insufficient = await PostAsync(client, Route, request, verifierOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, insufficient.StatusCode);

        string signerOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var insufficientVerifier = await PostAsync(client, Route, request, signerOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, insufficientVerifier.StatusCode);

        string both = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        using var unowned = await PostAsync(client, Route, request, both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unowned.StatusCode);

        string inactiveDid = await CreateDidAsync(client, both).ConfigureAwait(true);
        await using (var db = _fixture.CreateDbContext<HeroDbContext>())
        {
            var inactive = await db.Dids.SingleAsync(
                did => did.DidIdentifier == inactiveDid,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            inactive.Status = "deactivated";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        using var inactiveResponse = await PostAsync(client, Route,
            new { verifierDid = inactiveDid, audience = Audience, trustedIssuerDid = foreignDid, lifetimeSeconds = 120 },
            both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, inactiveResponse.StatusCode);
    }

    [Fact]
    public async Task MalformedIssuerAudienceAndLifetimeCannotObtainSignedVerifierRequest()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuer = NewKey();
        string issuerDid = DidFromKey(issuer);

        foreach (var request in new[]
        {
            new { verifierDid, audience = "http://verifier.example", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = "did:key:invalid", lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 301 },
            new { verifierDid, audience = Audience + "#fragment", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }
        })
        {
            using var denied = await PostAsync(client, Route, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        }
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
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-VC11-signed-verifier-request-test-secret-more-than-32-bytes"
                }));
        }
    }

    private static async Task<string> CreateDidAsync(HttpClient client, string token)
    {
        using var response = await PostAsync(client, "/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await ReadRequiredStringAsync(response, HttpStatusCode.Created, "did").ConfigureAwait(true);
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
        using var response = await client.PostAsync("/oauth2/token", form,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        return await ReadRequiredStringAsync(response, HttpStatusCode.OK, "access_token").ConfigureAwait(true);
    }

    private static async Task<string> ReadRequiredStringAsync(HttpResponseMessage response,
        HttpStatusCode expected, string property)
    {
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(response.StatusCode == expected,
            $"Expected {expected} but received {response.StatusCode}: {text}");
        using var json = JsonDocument.Parse(text);
        return json.RootElement.GetProperty(property).GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(HttpClient client,
        string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
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
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
