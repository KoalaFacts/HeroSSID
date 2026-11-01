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
/// Real guardian and successor keys, two HTTP hosts and one shared PostgreSQL
/// challenge store. Verification does not promote an issuer or grant authority.
/// </summary>
public sealed class IssuerGuardianRecoveryHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string ChallengeRoute = "/api/v1/credentials/issuer-guardian-recovery/challenge";
    private const string VerifyRoute = "/api/v1/credentials/issuer-guardian-recovery/verify";
    private const string CancelRoute = "/api/v1/credentials/issuer-guardian-recovery/cancel";
    private const string Audience = "https://verifier.example/issuer-guardian-recovery";
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task GenuineGuardianQuorumSucceedsAcrossHostsOnlyOnceAndFailedPolicyDoesNotBurnNonce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string secondToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardian1 = NewKey();
        using var guardian2 = NewKey();
        using var foreignGuardian = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string guardian1Did = DidFromKey(guardian1);
        string guardian2Did = DidFromKey(guardian2);

        using var issued = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        JsonElement challenge = await ReadJsonAsync(issued).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        Assert.Equal(Audience, challenge.GetProperty("audience").GetString());
        Assert.Equal(oldDid, challenge.GetProperty("trustedPreviousIssuerDid").GetString());

        string evidence = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardian1Did] = guardian1.Export(KeyBlobFormat.RawPrivateKey),
                [guardian2Did] = guardian2.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);

        using var untrusted = await PostAsync(second, VerifyRoute,
            new
            {
                evidenceJson = evidence, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { guardian1Did, DidFromKey(foreignGuardian) },
                requiredGuardianSignatures = 2
            }, secondToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, untrusted.StatusCode);
        JsonElement rejected = await ReadJsonAsync(untrusted).ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("successorIssuerDid").ValueKind);

        var validRequest = new
        {
            evidenceJson = evidence, audience = Audience, nonce,
            trustedPreviousIssuerDid = oldDid,
            trustedGuardianDids = new[] { guardian1Did, guardian2Did },
            requiredGuardianSignatures = 2
        };
        using var accepted = await PostAsync(second, VerifyRoute, validRequest, secondToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement valid = await ReadJsonAsync(accepted).ConfigureAwait(true);
        Assert.Equal("ValidRecoveryEvidence", valid.GetProperty("status").GetString());
        Assert.Equal(newDid, valid.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(first, VerifyRoute, validRequest, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        JsonElement replayBody = await ReadJsonAsync(replay).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayBody.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryCannotConsumeAnOrdinaryIssuerSuccessorChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardian1 = NewKey();
        using var guardian2 = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string guardian1Did = DidFromKey(guardian1);
        string guardian2Did = DidFromKey(guardian2);

        using var ordinary = await PostAsync(client, "/api/v1/credentials/issuer-successor/challenge",
            new { audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, ordinary.StatusCode);
        string nonce = (await ReadJsonAsync(ordinary).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string evidence = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardian1Did] = guardian1.Export(KeyBlobFormat.RawPrivateKey),
                [guardian2Did] = guardian2.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        using var denied = await PostAsync(client, VerifyRoute,
            new
            {
                evidenceJson = evidence, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { guardian1Did, guardian2Did },
                requiredGuardianSignatures = 2
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        JsonElement result = await ReadJsonAsync(denied).ConfigureAwait(true);
        Assert.Equal("Invalid", result.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryRoutesRequireScopesAndRejectInsecureOrAmbiguousPolicy()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var previous = NewKey();
        string oldDid = DidFromKey(previous);
        var issueRequest = new
        {
            audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120
        };
        using var anonymous = await client.PostAsJsonAsync(ChallengeRoute, issueRequest,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var missingManagement = await PostAsync(client, ChallengeRoute,
            issueRequest, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingManagement.StatusCode);

        string manageOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var missingVerify = await PostAsync(client, ChallengeRoute,
            issueRequest, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingVerify.StatusCode);
        using var invalidVerifyScope = await PostAsync(client, VerifyRoute,
            new { evidenceJson = "invalid" }, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, invalidVerifyScope.StatusCode);

        string both = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var insecure = await PostAsync(client, ChallengeRoute,
            new { audience = "http://verifier.example/recovery", previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, insecure.StatusCode);
        using var malformed = await PostAsync(client, VerifyRoute,
            new
            {
                evidenceJson = "invalid", audience = Audience,
                nonce = "short", trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = Array.Empty<string>(), requiredGuardianSignatures = 2
            }, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
    }

    [Fact]
    public async Task IncidentCancellationAcrossIndependentHostsBlocksGenuineRecovery()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string issuerToken = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string cancelToken = await GetTokenAsync(second, "credential:verify did:manage").ConfigureAwait(true);
        string verifyToken = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);

        using var previous = NewKey();
        using var successor = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string previousDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);
        string firstGuardianDid = DidFromKey(guardianOne);
        string secondGuardianDid = DidFromKey(guardianTwo);

        using var issued = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            issuerToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        string nonce = (await ReadJsonAsync(issued).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string proof = IssuerGuardianRecovery.Create(previousDid, successorDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstGuardianDid] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [secondGuardianDid] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);

        using var cancelled = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce, trustedPreviousIssuerDid = previousDid },
            cancelToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var repeated = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce, trustedPreviousIssuerDid = previousDid },
            cancelToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeated.StatusCode);

        using var rejected = await PostAsync(first, VerifyRoute,
            new
            {
                evidenceJson = proof, audience = Audience, nonce,
                trustedPreviousIssuerDid = previousDid,
                trustedGuardianDids = new[] { firstGuardianDid, secondGuardianDid },
                requiredGuardianSignatures = 2
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        JsonElement denied = await ReadJsonAsync(rejected).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryCancellationRequiresBothScopesAndDoesNotExposeUnknownChallenges()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var previous = NewKey();
        string previousDid = DidFromKey(previous);
        var cancellation = new
        {
            audience = Audience,
            nonce = new string('A', 43),
            trustedPreviousIssuerDid = previousDid
        };

        using var anonymous = await client.PostAsJsonAsync(CancelRoute, cancellation,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var cannotCancel = await PostAsync(client, CancelRoute,
            cancellation, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, cannotCancel.StatusCode);

        string manageOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var cannotCancelWithoutVerify = await PostAsync(client, CancelRoute,
            cancellation, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, cannotCancelWithoutVerify.StatusCode);

        string authorized = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var invalidNonce = await PostAsync(client, CancelRoute,
            new { audience = Audience, nonce = "short", trustedPreviousIssuerDid = previousDid },
            authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalidNonce.StatusCode);

        using var unknown = await PostAsync(client, CancelRoute,
            cancellation, authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unknown.StatusCode);
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
                    ["Jwt:Secret"] = "isolated-guardian-recovery-http-test-secret-more-than-32-bytes"
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
        JsonElement body = await ReadJsonAsync(response).ConfigureAwait(true);
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

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

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
