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
        using var body = JsonDocument.Parse(await issued.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
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
        using var verifiedJson = JsonDocument.Parse(await verified.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        Assert.Equal("SignedNotListed", verifiedJson.RootElement.GetProperty("status").GetString());
        Assert.Equal("member", verifiedJson.RootElement.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        using var replay = await PostAsync(client,
            "/api/v1/credentials/vcdm20/verify-presentation", proof, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        using var replayJson = JsonDocument.Parse(await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        Assert.Equal("Invalid", replayJson.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayJson.RootElement.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task TenantVerifierSignsExplicitVc2PolicyAndWalletRejectsAuthenticPolicySubstitution()
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

        var policyRequest = new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri, lifetimeSeconds = 120
        };
        using var issued = await PostAsync(client, Route, policyRequest, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        using var body = JsonDocument.Parse(
            await issued.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        string requestJwt = body.RootElement.GetProperty("signedRequestJwt").GetString()!;
        string nonce = body.RootElement.GetProperty("nonce").GetString()!;
        Assert.True(OfflineSignedPresentationRequest.TryReadPolicyBound(
            requestJwt, verifierDid, Audience, "MembershipCredential", Vocabulary,
            TimeProvider.System, out var requestChallenge));
        Assert.NotNull(requestChallenge);
        Assert.Equal("MembershipCredential", requestChallenge!.CredentialType);
        Assert.Equal(Vocabulary, requestChallenge.SubjectContextUri);
        Assert.Equal(nonce, requestChallenge.Nonce);
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            requestJwt, verifierDid, Audience, TimeProvider.System, out _));
        Assert.False(OfflineSignedPresentationRequest.TryReadPolicyBound(
            requestJwt, verifierDid, Audience, "AdministratorCredential", Vocabulary,
            TimeProvider.System, out _));

        using var subject = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credentialJwt = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary,
            subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        Assert.True(Vcdm20WalletDisclosure.TryPrepareRequiringSignedPolicy(
            requestJwt, verifierDid, Audience, "MembershipCredential", Vocabulary,
            issuerDid, credentialJwt, holderDid, TimeProvider.System, out var preview));
        Assert.NotNull(preview);

        // An independently valid issuer signature does not allow the same verifier
        // request to be silently repurposed for an administrator qualification.
        string adminCredential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "AdministratorCredential", Vocabulary,
            subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        Assert.False(Vcdm20WalletDisclosure.TryPrepare(
            requestJwt, verifierDid, Audience, "AdministratorCredential", Vocabulary,
            issuerDid, adminCredential, holderDid, TimeProvider.System, out _));
        var otherVocabulary = new Uri("https://issuer.example/contexts/admin/v1");
        string otherCredential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", otherVocabulary,
            subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        Assert.False(Vcdm20WalletDisclosure.TryPrepare(
            requestJwt, verifierDid, Audience, "MembershipCredential", otherVocabulary,
            issuerDid, otherCredential, holderDid, TimeProvider.System, out _));

        string proof = Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
            preview!, requestJwt, credentialJwt,
            holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        using var verified = await PostAsync(client,
            "/api/v1/credentials/vcdm20/verify-presentation", new
            {
                presentation = proof, revocationSnapshot = status,
                audience = Audience, nonce,
                expectedCredentialType = "MembershipCredential",
                subjectContextUri = Vocabulary.AbsoluteUri
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        using var result = JsonDocument.Parse(
            await verified.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        Assert.Equal("SignedNotListed", result.RootElement.GetProperty("status").GetString());
        Assert.Equal("member", result.RootElement.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var noContext = await PostAsync(client, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid,
            expectedCredentialType = "MembershipCredential", lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, noContext.StatusCode);
        using var noType = await PostAsync(client, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid,
            subjectContextUri = Vocabulary.AbsoluteUri, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, noType.StatusCode);
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
        using var anonymous = await client.PostAsJsonAsync(Route, request, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issueOnly = await GetTokenAsync(client, "credential:issue").ConfigureAwait(true);
        using var forbidden = await PostAsync(client, Route, request, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var insufficient = await PostAsync(client, Route, request, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, insufficient.StatusCode);

        string signerAuthorized = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        using var unowned = await PostAsync(client, Route, request, signerAuthorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unowned.StatusCode);
    }

    [Fact]
    public async Task RegisteredForeignTenantAndDeactivatedVerifierKeysCannotSign()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "did:manage credential:verify").ConfigureAwait(true);
        string foreignDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        string deactivatedDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        // Use genuinely enrolled, correctly encrypted keys rather than an
        // unregistered DID: the endpoint must reject a different tenant's
        // existing signer and this tenant's deactivated signer before decryption.
        await using (var db = _fixture.CreateDbContext<HeroDbContext>())
        {
            var foreign = await db.Dids.SingleAsync(
                did => did.DidIdentifier == foreignDid,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            var inactive = await db.Dids.SingleAsync(
                did => did.DidIdentifier == deactivatedDid,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            foreign.TenantId = Guid.NewGuid();
            inactive.Status = "deactivated";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        foreach (string verifierDid in new[] { foreignDid, deactivatedDid })
        {
            using var response = await PostAsync(client, Route, new
            {
                verifierDid, audience = Audience, trustedIssuerDid = issuerDid,
                lifetimeSeconds = 120
            }, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
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


    [Fact]
    public async Task SignedPolicyVerificationRejectsTamperingBeforeConsumingThenAcceptsAndSpendsOnce()
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
        using var signedResponse = await PostAsync(client, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        string signedRequestJwt = await ReadStringAsync(
            signedResponse, HttpStatusCode.Created, "signedRequestJwt").ConfigureAwait(true);

        using var subject = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            signedRequestJwt, verifierDid, Audience, credential, "MembershipCredential",
            Vocabulary, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = Vcdm20RevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System.GetUtcNow(), TimeProvider.System);

        const string verificationRoute = "/api/v1/credentials/vcdm20/verify-signed-policy-presentation";
        var original = new
        {
            signedRequestJwt, verifierDid, audience = Audience,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri,
            presentation, revocationSnapshot = status
        };
        // A valid verifier-signed request cannot be repurposed by supplying
        // an independently signed credential of a different type or vocabulary.
        // Denials before signature/status verification must not spend the nonce.
        using var wrongType = await PostAsync(client, verificationRoute, new
        {
            signedRequestJwt, verifierDid, audience = Audience,
            expectedCredentialType = "AdministratorCredential",
            subjectContextUri = Vocabulary.AbsoluteUri,
            presentation, revocationSnapshot = status
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, wrongType.StatusCode);
        using (var deniedType = JsonDocument.Parse(
            await wrongType.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true)))
        {
            Assert.Equal("Invalid", deniedType.RootElement.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, deniedType.RootElement.GetProperty("verifiedSubject").ValueKind);
        }

        using var wrongContext = await PostAsync(client, verificationRoute, new
        {
            signedRequestJwt, verifierDid, audience = Audience,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = "https://issuer.example/contexts/admin/v1",
            presentation, revocationSnapshot = status
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, wrongContext.StatusCode);
        using (var deniedContext = JsonDocument.Parse(
            await wrongContext.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true)))
        {
            Assert.Equal("Invalid", deniedContext.RootElement.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, deniedContext.RootElement.GetProperty("verifiedSubject").ValueKind);
        }

        string[] tamperedParts = signedRequestJwt.Split('.');
        tamperedParts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(signedRequestJwt).Replace(
                "MembershipCredential", "AdministratorCredential", StringComparison.Ordinal));
        using var tampered = await PostAsync(client, verificationRoute, new
        {
            signedRequestJwt = string.Join('.', tamperedParts), verifierDid, audience = Audience,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary.AbsoluteUri,
            presentation, revocationSnapshot = status
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, tampered.StatusCode);
        using (var invalid = JsonDocument.Parse(
            await tampered.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true)))
        {
            Assert.Equal("Invalid", invalid.RootElement.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, invalid.RootElement.GetProperty("verifiedSubject").ValueKind);
        }

        using var accepted = await PostAsync(client, verificationRoute, original, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using (var valid = JsonDocument.Parse(
            await accepted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true)))
        {
            Assert.Equal("SignedNotListed", valid.RootElement.GetProperty("status").GetString());
            Assert.Equal("member", valid.RootElement.GetProperty("verifiedSubject")
                .GetProperty("role").GetString());
        }

        using var replay = await PostAsync(client, verificationRoute, original, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        using var replayResult = JsonDocument.Parse(
            await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        Assert.Equal("Invalid", replayResult.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayResult.RootElement.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task SignedPolicyVerificationRejectsAuthenticLegacyUnboundRequest()
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

        using var legacyResponse = await PostAsync(client, Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        string legacyRequest = await ReadStringAsync(
            legacyResponse, HttpStatusCode.Created, "signedRequestJwt").ConfigureAwait(true);
        using var subject = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            legacyRequest, verifierDid, Audience, credential, "MembershipCredential",
            Vocabulary, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = Vcdm20RevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);

        using var rejected = await PostAsync(client,
            "/api/v1/credentials/vcdm20/verify-signed-policy-presentation", new
            {
                signedRequestJwt = legacyRequest, verifierDid, audience = Audience,
                expectedCredentialType = "MembershipCredential",
                subjectContextUri = Vocabulary.AbsoluteUri, presentation, revocationSnapshot = status
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        using var denied = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
        Assert.Equal("Invalid", denied.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.RootElement.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task SignedPolicyVerificationRequiresVerifierAuthentication()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        const string route = "/api/v1/credentials/vcdm20/verify-signed-policy-presentation";
        using var unauthenticated = await client.PostAsJsonAsync(route, new { },
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        string issuerOnly = await GetTokenAsync(client, "credential:issue").ConfigureAwait(true);
        using var forbidden = await PostAsync(client, route, new { }, issuerOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
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
        string json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
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
