using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
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
/// End-to-end signed verifier HTTP requests, real issuer/holder Ed25519 keys and
/// isolated PostgreSQL migrations. No external wallet or production database.
/// </summary>
public sealed class Vcdm20SignedVerifierRequestHttpTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string Route = "/api/v1/credentials/vcdm20/signed-presentation-request";
    private const string Audience = "https://verifier.example/receive";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task TenantOwnedVerifierSignsRequestForIndependentHolderAndProofIsSpentOnlyOnce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var issued = await PostAsync(client, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        using var body = JsonDocument.Parse(await issued.Content.ReadAsStringAsync().ConfigureAwait(true));
        string requestJwt = body.RootElement.GetProperty("signedRequestJwt").GetString()!;
        Assert.Equal(verifierDid, body.RootElement.GetProperty("verifierDid").GetString());
        Assert.Equal(Audience, body.RootElement.GetProperty("audience").GetString());
        Assert.Equal(issuerDid, body.RootElement.GetProperty("trustedIssuerDid").GetString());

        Assert.True(OfflineSignedPresentationRequest.TryRead(
            requestJwt, verifierDid, Audience, TimeProvider.System, out var challenge));
        Assert.NotNull(challenge);
        Assert.Equal(body.RootElement.GetProperty("nonce").GetString(), challenge.Nonce);
        Assert.Equal(issuerDid, challenge.TrustedIssuerDid);
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            requestJwt, holderDid, Audience, TimeProvider.System, out _));
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            requestJwt, verifierDid, "https://wrong.example/receive", TimeProvider.System, out _));
        string[] parts = requestJwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(requestJwt).Replace(
                Audience, "https://forged.example/receive", StringComparison.Ordinal));
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            string.Join('.', parts), verifierDid, Audience, TimeProvider.System, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string originalCredential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            requestJwt, verifierDid, Audience, originalCredential, "MembershipCredential",
            Vocabulary, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);

        using var holderPayload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        Assert.Equal(holderDid, holderPayload.RootElement.GetProperty("holder").GetString());
        Assert.Equal(challenge.Nonce, holderPayload.RootElement.GetProperty("nonce").GetString());
        string enveloped = holderPayload.RootElement.GetProperty("verifiableCredential")[0]
            .GetProperty("id").GetString()!;
        Assert.Equal("data:application/vc+jwt," + originalCredential, enveloped);

        string signedStatus = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        var proof = new
        {
            presentation, revocationSnapshot = signedStatus, audience = Audience,
            nonce = challenge.Nonce, expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri
        };
        using var verified = await PostAsync(client,
            "/api/v1/credentials/vcdm20/verify-presentation", proof, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        using var verifiedJson = JsonDocument.Parse(await verified.Content.ReadAsStringAsync().ConfigureAwait(true));
        Assert.Equal("SignedNotListed", verifiedJson.RootElement.GetProperty("status").GetString());
        Assert.Equal("member", verifiedJson.RootElement.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        using var replay = await PostAsync(client,
            "/api/v1/credentials/vcdm20/verify-presentation", proof, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        using var replayJson = JsonDocument.Parse(await replay.Content.ReadAsStringAsync().ConfigureAwait(true));
        Assert.Equal("Invalid", replayJson.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayJson.RootElement.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task AnonymousWrongScopeAndForeignVerifierDidCannotSign()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var outsideKey = NewKey();
        string outsideDid = DidFromKey(outsideKey);
        var request = new { verifierDid = outsideDid, audience = Audience,
            trustedIssuerDid = outsideDid, lifetimeSeconds = 120 };
        using var anonymous = await client.PostAsJsonAsync(Route, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issueOnly = await GetTokenAsync(client, "credential:issue").ConfigureAwait(true);
        using var forbidden = await PostAsync(client, Route, request, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var unowned = await PostAsync(client, Route, request, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unowned.StatusCode);
    }

    [Fact]
    public async Task InvalidHttpsAudienceIssuerAndChallengeLifetimeAreRejected()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        foreach (var request in new[]
        {
            new { verifierDid, audience = "http://verifier.example/insecure", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = "did:key:invalid", lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 301 },
            new { verifierDid, audience = Audience + "#fragment", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }
        })
        {
            using var invalid = await PostAsync(client, Route, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
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
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-signed-verifier-request-test-secret-with-at-least-32-bytes"
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
        HttpResponseMessage response, HttpStatusCode status, string name)
    {
        string json = await response.Content.ReadAsStringAsync().ConfigureAwait(true);
        Assert.True(response.StatusCode == status,
            $"Expected {status} but received {response.StatusCode}: {json}");
        using var document = JsonDocument.Parse(json);
        return document.RootElement.GetProperty(name).GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request).ConfigureAwait(true);
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
