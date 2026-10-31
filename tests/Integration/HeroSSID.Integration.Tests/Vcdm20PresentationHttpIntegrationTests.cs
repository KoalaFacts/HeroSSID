using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
/// Real, disposable PostgreSQL and independent HTTP host instances prove that
/// verifier-owned VC2 challenges persist and can be consumed only once across replicas.
/// This does not connect an external wallet or a production database.
/// </summary>
public sealed class Vcdm20PresentationHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string Audience = "https://verifier.example/holder-proof";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task TwoIndependentHttpHostsUseOneDurableChallengeForRealHolderIssuerAndStatusProof()
    {
        var ct = TestContext.Current.CancellationToken;
        await using (var setup = _fixture.CreateDbContext<HeroDbContext>())
        {
            await setup.Database.MigrateAsync(ct).ConfigureAwait(true);
        }

        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();

        using var issuerKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holderKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var verifierKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        string verifierDid = DidFromKey(verifierKey);

        using var anonymous = await first.PostAsJsonAsync(
            "/api/v1/credentials/vcdm20/presentation-challenge",
            new { audience = Audience, trustedIssuerDid = issuerDid }, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var issued = await first.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/presentation-challenge",
            new { audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var result = await issued.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct)
            .ConfigureAwait(true);
        var challenge = new PresentationChallenge
        {
            Audience = result.GetProperty("audience").GetString()!,
            TrustedIssuerDid = result.GetProperty("trustedIssuerDid").GetString()!,
            Nonce = result.GetProperty("nonce").GetString()!,
            ExpiresAt = result.GetProperty("expiresAt").GetDateTimeOffset()
        };
        Assert.Equal(Audience, challenge.Audience);
        Assert.Equal(issuerDid, challenge.TrustedIssuerDid);

        var now = TimeProvider.System.GetUtcNow();
        string signedVerifierRequest = OfflineSignedPresentationRequest.Create(
            challenge, verifierDid, verifierKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        string originalIssuerCredential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1),
            now.AddMinutes(10));
        string signedHolderPresentation = Vcdm20JosePresentation.Create(
            signedVerifierRequest, verifierDid, Audience, originalIssuerCredential,
            "MembershipCredential", Vocabulary, holderDid,
            holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string signedStatus = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);

        // The challenge was created by firstHost, but secondHost has a separate
        // scoped service provider and connection pool against the same temporary DB.
        var proof = new
        {
            presentation = signedHolderPresentation,
            revocationSnapshot = signedStatus,
            audience = Audience,
            nonce = challenge.Nonce,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri
        };
        using var verified = await second.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify-presentation", proof, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var accepted = await verified.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct)
            .ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.GetProperty("status").GetString());
        Assert.Equal("member", accepted.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await first.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify-presentation", proof, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var repeated = await replay.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct)
            .ConfigureAwait(true);
        Assert.Equal("Invalid", repeated.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, repeated.GetProperty("verifiedSubject").ValueKind);
    }


    [Fact]
    public async Task CancelledChallengeCannotAcceptGenuineHolderProofAcrossTwoHttpHosts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using (var setup = _fixture.CreateDbContext<HeroDbContext>())
        {
            await setup.Database.MigrateAsync(ct).ConfigureAwait(true);
        }

        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        using var issuerKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holderKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var verifierKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        string verifierDid = DidFromKey(verifierKey);

        using var issued = await first.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/presentation-challenge",
            new { audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var result = await issued.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct)
            .ConfigureAwait(true);
        var challenge = new PresentationChallenge
        {
            Audience = result.GetProperty("audience").GetString()!,
            TrustedIssuerDid = result.GetProperty("trustedIssuerDid").GetString()!,
            Nonce = result.GetProperty("nonce").GetString()!,
            ExpiresAt = result.GetProperty("expiresAt").GetDateTimeOffset()
        };

        var now = TimeProvider.System.GetUtcNow();
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge, verifierDid, verifierKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        string credential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1),
            now.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            signedRequest, verifierDid, Audience, credential,
            "MembershipCredential", Vocabulary, holderDid,
            holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);

        const string cancelRoute = "/api/v1/credentials/vcdm20/cancel-presentation-challenge";
        using var cancelled = await second.AuthorizedPostAsJsonAsync(
            cancelRoute, new { audience = Audience, nonce = challenge.Nonce }, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var repeated = await first.AuthorizedPostAsJsonAsync(
            cancelRoute, new { audience = Audience, nonce = challenge.Nonce }, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeated.StatusCode);

        using var rejected = await first.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify-presentation",
            new
            {
                presentation, revocationSnapshot = snapshot, audience = Audience,
                nonce = challenge.Nonce, expectedCredentialType = "MembershipCredential",
                subjectContextUri = Vocabulary.AbsoluteUri
            }, ct).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        var denied = await rejected.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct)
            .ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task CancellationRequiresVerifierAuthorizationAndHidesUnknownNonce()
    {
        var ct = TestContext.Current.CancellationToken;
        await using (var setup = _fixture.CreateDbContext<HeroDbContext>())
        {
            await setup.Database.MigrateAsync(ct).ConfigureAwait(true);
        }

        await using var host = NewHost();
        using var client = host.CreateClient();
        const string route = "/api/v1/credentials/vcdm20/cancel-presentation-challenge";

        using var anonymous = await client.PostAsJsonAsync(
            route, new { audience = Audience, nonce = new string('A', 43) }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var malformed = await client.AuthorizedPostAsJsonAsync(
            route, new { audience = Audience, nonce = "not-a-valid-nonce" }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);

        using var nonCanonical = await client.AuthorizedPostAsJsonAsync(
            route, new { audience = Audience, nonce = new string('!', 43) }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, nonCanonical.StatusCode);

        using var insecureAudience = await client.AuthorizedPostAsJsonAsync(
            route, new { audience = "http://verifier.example/holder-proof", nonce = new string('A', 43) }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, insecureAudience.StatusCode);

        using var unknown = await client.AuthorizedPostAsJsonAsync(
            route, new { audience = Audience, nonce = new string('A', 43) }, ct)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unknown.StatusCode);
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
                    ["Jwt:Secret"] = "isolated-VC2-HTTP-test-secret-with-more-than-32-bytes"
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
}
