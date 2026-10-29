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

    private WebApplicationFactory<Program> NewHost() =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = _fixture.ConnectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-VC2-HTTP-test-secret-with-more-than-32-bytes"
                }));
        });

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
