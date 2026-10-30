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
/// Two real HTTP hosts sharing isolated PostgreSQL exercise VC1.1 issuer proof,
/// independent holder control, tenant-scoped challenge consumption and issuer status.
/// No production data or third-party wallet is involved.
/// </summary>
public sealed class JwtVcJsonPresentationHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string ChallengePath = "/api/v1/credentials/jwt-vc-json/presentation-challenge";
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify-presentation";
    private const string Audience = "https://verifier.example/membership";
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task IndependentHttpHostsAcceptBothRealSignaturesOnceAndRejectReplay()
    {
        await MigrateAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        var proof = await CreateProofAsync(first).ConfigureAwait(true);
        using var accepted = await second.AuthorizedPostAsJsonAsync(VerifyPath, proof.ValidRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var outcome = await ReadJsonAsync(accepted).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", outcome.GetProperty("status").GetString());
        Assert.Equal("member", outcome.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await first.AuthorizedPostAsJsonAsync(VerifyPath, proof.ValidRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var rejected = await ReadJsonAsync(replay).ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task AuthenticRevocationRejectsSubjectAndSpendsOneUseChallenge()
    {
        await MigrateAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        var proof = await CreateProofAsync(client).ConfigureAwait(true);
        object revokedRequest = Request(proof.Presentation, proof.RevokedStatus, proof.Nonce);
        using var revoked = await client.AuthorizedPostAsJsonAsync(VerifyPath, revokedRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var denied = await ReadJsonAsync(revoked).ConfigureAwait(true);
        Assert.Equal("Revoked", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("verifiedSubject").ValueKind);

        using var replay = await client.AuthorizedPostAsJsonAsync(VerifyPath, proof.ValidRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal("Invalid", (await ReadJsonAsync(replay).ConfigureAwait(true))
            .GetProperty("status").GetString());
    }

    [Fact]
    public async Task ForgedHolderAndForeignIssuerSnapshotNeverReleaseClaims()
    {
        await MigrateAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        var proof = await CreateProofAsync(client).ConfigureAwait(true);
        string[] parts = proof.Presentation.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(proof.Presentation)
            .Replace("member", "administrator", StringComparison.Ordinal));
        string forged = string.Join('.', parts);
        using var forgedResponse = await client.AuthorizedPostAsJsonAsync(
            VerifyPath, Request(forged, proof.CleanStatus, proof.Nonce), TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, forgedResponse.StatusCode);
        var forgedBody = await ReadJsonAsync(forgedResponse).ConfigureAwait(true);
        Assert.Equal("Invalid", forgedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, forgedBody.GetProperty("verifiedSubject").ValueKind);

        using var foreign = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string foreignStatus = JwtVcJsonRevocationSnapshot.Create(
            DidFromKey(foreign), [], foreign.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        using var foreignResponse = await client.AuthorizedPostAsJsonAsync(
            VerifyPath, Request(proof.Presentation, foreignStatus, proof.Nonce), TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", (await ReadJsonAsync(foreignResponse).ConfigureAwait(true))
            .GetProperty("status").GetString());
        // The authentic holder proof spent the nonce before rejecting the
        // foreign issuer's status, so even a later correct snapshot cannot replay.
        using var replay = await client.AuthorizedPostAsJsonAsync(VerifyPath, proof.ValidRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        var replayOutcome = await ReadJsonAsync(replay).ConfigureAwait(true);
        Assert.Equal("Invalid", replayOutcome.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayOutcome.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task BothRoutesRequireVerifyScopeAndRejectMalformedVerifierPolicy()
    {
        await MigrateAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var issueRequest = new
        {
            audience = Audience,
            trustedIssuerDid = DidFromKey(issuer),
            lifetimeSeconds = 120
        };
        using var anonymousIssue = await client.PostAsJsonAsync(ChallengePath, issueRequest, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousIssue.StatusCode);
        string issueOnly = await ScopeTokenAsync(client, "credential:issue").ConfigureAwait(true);
        using var forbiddenIssue = await PostWithBearerAsync(client, ChallengePath, issueRequest, issueOnly)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenIssue.StatusCode);
        using var anonymousVerify = await client.PostAsJsonAsync(VerifyPath, new { }, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousVerify.StatusCode);
        using var forbiddenVerify = await PostWithBearerAsync(client, VerifyPath, new { }, issueOnly)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenVerify.StatusCode);
        using var invalid = await client.AuthorizedPostAsJsonAsync(ChallengePath,
            new { audience = "http://attacker.example", trustedIssuerDid = DidFromKey(issuer) }, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    private static async Task<Proof> CreateProofAsync(HttpClient client)
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holder = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var verifier = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string issuerDid = DidFromKey(issuer);
        string holderDid = DidFromKey(holder);
        string verifierDid = DidFromKey(verifier);
        using var issueResponse = await client.AuthorizedPostAsJsonAsync(ChallengePath,
            new { audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }, TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issueResponse.StatusCode);
        var issued = await ReadJsonAsync(issueResponse).ConfigureAwait(true);
        var challenge = new PresentationChallenge
        {
            Audience = issued.GetProperty("audience").GetString()!,
            TrustedIssuerDid = issued.GetProperty("trustedIssuerDid").GetString()!,
            Nonce = issued.GetProperty("nonce").GetString()!,
            ExpiresAt = issued.GetProperty("expiresAt").GetDateTimeOffset()
        };
        string signedRequest = OfflineSignedPresentationRequest.Create(challenge,
            verifierDid, verifier.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid,
            CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(5));
        string presentation = JwtVcJsonPresentation.Create(signedRequest, verifierDid,
            Audience, credential, CredentialType, Vocabulary, holderDid,
            holder.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuer.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [credential],
            issuer.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        return new Proof(presentation, clean, revoked, challenge.Nonce);
    }

    private static object Request(string presentation, string snapshot, string nonce) => new
    {
        presentation,
        revocationSnapshot = snapshot,
        audience = Audience,
        nonce,
        expectedCredentialType = CredentialType,
        subjectContextUri = Vocabulary.AbsoluteUri
    };

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken).ConfigureAwait(true);

    private async Task MigrateAsync()
    {
        await using var context = _fixture.CreateDbContext<HeroDbContext>();
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
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
                    ["Jwt:Secret"] = "isolated-VC11-HTTP-test-secret-with-more-than-32-bytes"
                }));
        }
    }

    private static string DidFromKey(Key key)
    {
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }

    private static async Task<string> ScopeTokenAsync(HttpClient client, string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await client.PostAsync("/oauth2/token", form, TestContext.Current.CancellationToken).ConfigureAwait(true);
        var payload = await ReadJsonAsync(response).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return payload.GetProperty("access_token").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostWithBearerAsync(
        HttpClient client, string path, object body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private sealed record Proof(string Presentation, string CleanStatus, string RevokedStatus, string Nonce)
    {
        public object ValidRequest => Request(Presentation, CleanStatus, Nonce);
    }
}
