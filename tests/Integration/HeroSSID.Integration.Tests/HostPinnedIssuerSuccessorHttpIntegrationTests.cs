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
    private const string CancelRoute = "/api/v1/credentials/issuer-successor/host-pinned-cancel";
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
            new { policyId = "issuer-migration", nonce, attestation }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, unpinnedVerification.StatusCode);
        Assert.Equal("Invalid",
            (await BodyAsync(unpinnedVerification).ConfigureAwait(true))
                .GetProperty("status").GetString());

        // A caller cannot inject its own preapproved successor DID even if a
        // different host already issued the original durable challenge.
        using var callerOverride = await PostAsync(second, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation,
                preapprovedSuccessorIssuerDid = approvedDid }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, callerOverride.StatusCode);

        using var accepted = await PostAsync(first, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation }, token).ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(accepted).ConfigureAwait(true)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task LegacyUnpinnedVerifierCannotConsumeHostPinnedSuccessorNonce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        using var rogue = NewKey();
        await using var host = NewHost(DidFromKey(previous), DidFromKey(approved));
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        string nonce = await IssueNonceAsync(client, token).ConfigureAwait(true);
        string unauthorizedProof = Proof(previous, rogue, nonce);

        // Even two authentic old/new signatures for a different successor must
        // never consume the nonce through the legacy key-control-only route.
        using var legacy = await PostAsync(client,
            "/api/v1/credentials/issuer-successor/verify",
            new { audience = Audience, nonce, attestation = unauthorizedProof }, token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, legacy.StatusCode);
        Assert.Equal("Invalid",
            (await BodyAsync(legacy).ConfigureAwait(true)).GetProperty("status").GetString());

        string approvedProof = Proof(previous, approved, nonce);
        using var accepted = await PostAsync(client, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation = approvedProof }, token)
            .ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(accepted).ConfigureAwait(true)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task HostPinnedEndpointsRequireAuthenticationAndVerifierScope()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        await using var host = NewHost(DidFromKey(previous), DidFromKey(approved));
        using var client = host.CreateClient();
        var challenge = new { policyId = "issuer-migration", lifetimeSeconds = 120 };
        using var anonymousIssue = await client.PostAsJsonAsync(IssueRoute, challenge,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousIssue.StatusCode);
        using var anonymousVerify = await client.PostAsJsonAsync(VerifyRoute,
            new { policyId = "issuer-migration", nonce = new string('A', 43),
                attestation = "invalid" }, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousVerify.StatusCode);

        string unrelated = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var forbiddenIssue = await PostAsync(client, IssueRoute,
            challenge, unrelated).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenIssue.StatusCode);
        using var forbiddenVerify = await PostAsync(client, VerifyRoute,
            new { policyId = "issuer-migration", nonce = new string('A', 43),
                attestation = "invalid" }, unrelated).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenVerify.StatusCode);
    }


    [Fact]
    public async Task OperatorCanCancelHostPinnedSuccessorChallengeAcrossReplicasBeforeVerification()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        string previousDid = DidFromKey(previous);
        string approvedDid = DidFromKey(approved);
        await using var issuingHost = NewHost(previousDid, approvedDid);
        await using var cancellingHost = NewHost(previousDid, approvedDid);
        using var first = issuingHost.CreateClient();
        using var second = cancellingHost.CreateClient();
        string verifierToken = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);
        string operatorToken = await GetTokenAsync(second, "credential:verify did:manage").ConfigureAwait(true);

        string nonce = await IssueNonceAsync(first, verifierToken).ConfigureAwait(true);
        string signedProof = Proof(previous, approved, nonce);
        var cancellation = new { policyId = "issuer-migration", nonce };
        using var cancelled = await PostAsync(second, CancelRoute, cancellation, operatorToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);

        using var afterCancellation = await PostAsync(first, VerifyRoute,
            new { policyId = "issuer-migration", nonce, attestation = signedProof },
            verifierToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, afterCancellation.StatusCode);
        Assert.Equal("Invalid", (await BodyAsync(afterCancellation).ConfigureAwait(true))
            .GetProperty("status").GetString());

        using var repeated = await PostAsync(second, CancelRoute, cancellation, operatorToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeated.StatusCode);

        string healthyNonce = await IssueNonceAsync(first, verifierToken).ConfigureAwait(true);
        using var healthy = await PostAsync(first, VerifyRoute,
            new { policyId = "issuer-migration", nonce = healthyNonce,
                attestation = Proof(previous, approved, healthyNonce) }, verifierToken)
            .ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(healthy).ConfigureAwait(true)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task HostPinnedCancellationRequiresOperatorScopesAndCannotCrossPolicyBoundary()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var approved = NewKey();
        string previousDid = DidFromKey(previous);
        string approvedDid = DidFromKey(approved);
        await using var pinnedHost = NewHost(previousDid, approvedDid);
        await using var unpinnedHost = NewHost(previousDid, approvedDid, configurePin: false);
        using var pinned = pinnedHost.CreateClient();
        using var unpinned = unpinnedHost.CreateClient();
        string verifierToken = await GetTokenAsync(pinned, "credential:verify")
            .ConfigureAwait(true);
        string managementToken = await GetTokenAsync(pinned, "did:manage")
            .ConfigureAwait(true);
        string operatorToken = await GetTokenAsync(pinned, "credential:verify did:manage")
            .ConfigureAwait(true);
        string nonce = await IssueNonceAsync(pinned, verifierToken).ConfigureAwait(true);
        var request = new { policyId = "issuer-migration", nonce };

        using var anonymous = await pinned.PostAsJsonAsync(CancelRoute, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using var verifyOnly = await PostAsync(pinned, CancelRoute, request, verifierToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, verifyOnly.StatusCode);
        using var manageOnly = await PostAsync(pinned, CancelRoute, request, managementToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, manageOnly.StatusCode);
        using var badNonce = await PostAsync(pinned, CancelRoute,
            new { policyId = "issuer-migration", nonce = "invalid" }, operatorToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, badNonce.StatusCode);

        using var unknownPolicy = await PostAsync(pinned, CancelRoute,
            new { policyId = "unregistered", nonce }, operatorToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unknownPolicy.StatusCode);
        using var unconfiguredHost = await PostAsync(unpinned, CancelRoute, request, operatorToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unconfiguredHost.StatusCode);

        using var stillAccepted = await PostAsync(pinned, VerifyRoute,
            new { policyId = "issuer-migration", nonce,
                attestation = Proof(previous, approved, nonce) }, verifierToken)
            .ConfigureAwait(true);
        Assert.Equal("ValidPinnedKeyContinuity",
            (await BodyAsync(stillAccepted).ConfigureAwait(true)).GetProperty("status").GetString());
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
