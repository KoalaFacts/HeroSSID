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
/// Two independent HTTP hosts, an isolated PostgreSQL challenge store, and real
/// old/new Ed25519 issuer keys. The proof is NOT issuer enrollment or trust promotion.
/// </summary>
public sealed class IssuerSuccessorHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string ChallengeRoute = "/api/v1/credentials/issuer-successor/challenge";
    private const string VerifyRoute = "/api/v1/credentials/issuer-successor/verify";
    private const string Audience = "https://verifier.example/issuer-successor";
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task IndependentOldAndNewSignaturesAreAcceptedOnlyOnceAcrossHttpHosts()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        string previousDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);

        using var challengeResponse = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, challengeResponse.StatusCode);
        var challenge = await challengeResponse.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        Assert.Equal(Audience, challenge.GetProperty("audience").GetString());
        Assert.Equal(previousDid, challenge.GetProperty("trustedPreviousIssuerDid").GetString());

        string attestation = IssuerKeySuccessorAttestation.Create(
            previousDid, successorDid,
            previous.Export(KeyBlobFormat.RawPrivateKey),
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Uri(Audience), nonce, TimeProvider.System);
        var request = new { attestation, audience = Audience, nonce };
        string secondToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var accepted = await PostAsync(second, VerifyRoute, request, secondToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var valid = await accepted.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("ValidKeyContinuity", valid.GetProperty("status").GetString());
        Assert.Equal(successorDid, valid.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(first, VerifyRoute, request, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var denied = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task ForeignIssuerProofCannotSpendVerifierOwnedChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var foreignPrevious = NewKey();
        string previousDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);

        using var issued = await PostAsync(client, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var challenge = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        string forgedPolicy = IssuerKeySuccessorAttestation.Create(
            DidFromKey(foreignPrevious), successorDid,
            foreignPrevious.Export(KeyBlobFormat.RawPrivateKey),
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Uri(Audience), nonce, TimeProvider.System);
        using var denied = await PostAsync(client, VerifyRoute,
            new { attestation = forgedPolicy, audience = Audience, nonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var invalid = await denied.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", invalid.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, invalid.GetProperty("successorIssuerDid").ValueKind);

        string genuine = IssuerKeySuccessorAttestation.Create(
            previousDid, successorDid,
            previous.Export(KeyBlobFormat.RawPrivateKey),
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Uri(Audience), nonce, TimeProvider.System);
        using var accepted = await PostAsync(client, VerifyRoute,
            new { attestation = genuine, audience = Audience, nonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var valid = await accepted.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("ValidKeyContinuity", valid.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AuthenticatedVerifierAndStrongInputsAreMandatory()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var previous = NewKey();
        string previousDid = DidFromKey(previous);
        var request = new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 };

        using var anonymous = await client.PostAsJsonAsync(ChallengeRoute, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string unrelatedScope = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var forbidden = await PostAsync(client, ChallengeRoute, request, unrelatedScope)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using var forbiddenVerify = await PostAsync(client, VerifyRoute,
            new { attestation = "x", audience = Audience, nonce = new string('A', 43) },
            unrelatedScope).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenVerify.StatusCode);

        string token = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        foreach (var bad in new[]
        {
            new { audience = "http://verifier.example", previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            new { audience = Audience + "#fragment", previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            new { audience = Audience, previousIssuerDid = "did:key:invalid", lifetimeSeconds = 120 },
            new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 301 }
        })
        {
            using var denied = await PostAsync(client, ChallengeRoute, bad, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        }
        using var malformed = await PostAsync(client, VerifyRoute,
            new { attestation = "not-a-dual-signature", audience = Audience, nonce = "short" },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
    }


    [Fact]
    public async Task SignedVerifierChallengeAuthenticatesDestinationAndDrivesTwoKeyProofAcrossHosts()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        using var created = await PostAsync(first, "/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var didBody = await created.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string verifierDid = didBody.GetProperty("did").GetString()!;
        using var previous = NewKey();
        using var successor = NewKey();
        string previousDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);

        using var issued = await PostAsync(first,
            "/api/v1/credentials/issuer-successor/signed-challenge",
            new { verifierDid, audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var body = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = body.GetProperty("signedRequestJwt").GetString()!;
        Assert.Equal(verifierDid, body.GetProperty("verifierDid").GetString());
        Assert.Equal(Audience, body.GetProperty("audience").GetString());
        Assert.Equal(previousDid, body.GetProperty("trustedPreviousIssuerDid").GetString());
        Assert.Equal(3, signed.Split('.').Length);
        string nonce = body.GetProperty("nonce").GetString()!;
        string attestation = IssuerKeySuccessorAttestation.Create(previousDid,
            successorDid, previous.Export(KeyBlobFormat.RawPrivateKey),
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Uri(Audience), nonce, TimeProvider.System);
        string secondToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        var proof = new { attestation, audience = Audience, nonce };
        using var accepted = await PostAsync(second, VerifyRoute, proof, secondToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var success = await accepted.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("ValidKeyContinuity", success.GetProperty("status").GetString());
        Assert.Equal(successorDid, success.GetProperty("successorIssuerDid").GetString());
        using var replay = await PostAsync(first, VerifyRoute, proof, token).ConfigureAwait(true);
        var replayBody = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
    }

    [Fact]
    public async Task SignedVerifierChallengeRejectsAnonymousMissingScopesAndUnownedSigner()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var foreign = NewKey();
        string foreignDid = DidFromKey(foreign);
        var request = new
        {
            verifierDid = foreignDid, audience = Audience,
            previousIssuerDid = foreignDid, lifetimeSeconds = 120
        };
        const string route = "/api/v1/credentials/issuer-successor/signed-challenge";
        using var anonymous = await client.PostAsJsonAsync(route, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var noSigner = await PostAsync(client, route, request, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, noSigner.StatusCode);
        string manageOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var noVerify = await PostAsync(client, route, request, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, noVerify.StatusCode);
        string both = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var unowned = await PostAsync(client, route, request, both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unowned.StatusCode);
        using var invalid = await PostAsync(client, route,
            new { verifierDid = foreignDid, audience = "http://insecure.example",
                previousIssuerDid = foreignDid, lifetimeSeconds = 120 }, both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
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
                    ["Jwt:Secret"] = "isolated-issuer-successor-http-test-secret-more-than-32-bytes"
                }));
        }
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
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        return body.GetProperty("access_token").GetString()!;
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
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
