using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class Vcdm20PresentationEndpointTests
{
    private const string Audience = "https://verifier.example/present";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/context/membership/v1");
    private static readonly DateTimeOffset Epoch = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private readonly Clock _clock = new(Epoch);
    private readonly Tenant _tenant = new();
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();

    [Fact]
    public async Task VerifierCanIssueTenantBoundRandomChallengeForSignedHolderPresentation()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (status, issued) = await JsonAsync(Vcdm20PresentationEndpoints.Issue(
            new IssueVcdm20PresentationChallengeRequest
            {
                Audience = Audience, TrustedIssuerDid = _issuer.Did, LifetimeSeconds = 120
            }, store, _tenant)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status201Created, status);
        Assert.Equal(Audience, issued.GetProperty("audience").GetString());
        Assert.Equal(_issuer.Did, issued.GetProperty("trustedIssuerDid").GetString());
        string nonce = Assert.IsType<string>(issued.GetProperty("nonce").GetString());
        Assert.Equal(43, nonce.Length);
        var challenge = store.Find(_tenant.Id, Audience, nonce);
        Assert.NotNull(challenge);
        Assert.Equal(_issuer.Did, challenge.TrustedIssuerDid);
        Assert.Null(store.Find(Guid.NewGuid(), Audience, nonce));
    }

    [Fact]
    public async Task RealIssuerAndHolderSignaturesWithStatusSucceedOnceWithoutIssuerDatabase()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var request = Request(challenge, presentation, snapshot);
        var (status, accepted) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            request, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal("SignedNotListed", accepted.GetProperty("status").GetString());
        Assert.Equal("member", accepted.GetProperty("verifiedSubject").GetProperty("role").GetString());

        var (replayStatus, replay) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            request, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, replayStatus);
        Assert.Equal("Invalid", replay.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replay.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task AuthenticIssuerRevocationIsRejectedAndConsumesChallenge()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, _) = CreatePresentation(store);
        string credential = EnclosedCredential(presentation);
        string revokedSnapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, _clock.GetUtcNow(), _clock);
        var request = Request(challenge, presentation, revokedSnapshot);
        var (_, first) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            request, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Revoked", first.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, first.GetProperty("verifiedSubject").ValueKind);
        var (_, repeated) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            request, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", repeated.GetProperty("status").GetString());
    }

    [Fact]
    public async Task TamperedHolderProofAndForeignTenantFailWithoutLeakingClaimsOrSpendingGoodChallenge()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var parts = presentation.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(presentation)
            .Replace("member", "administrator", StringComparison.Ordinal));
        string forged = string.Join('.', parts);
        var (_, forgedResult) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            Request(challenge, forged, snapshot), store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", forgedResult.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, forgedResult.GetProperty("verifiedSubject").ValueKind);
        var (_, foreignResult) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            Request(challenge, presentation, snapshot), store, new Tenant(), _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", foreignResult.GetProperty("status").GetString());
        var (_, validResult) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            Request(challenge, presentation, snapshot), store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", validResult.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ExpiredChallengeAndInvalidIssuerSnapshotFailClosed()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var (_, wrongSnapshot) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            Request(challenge, presentation, snapshot + "corrupted"), store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", wrongSnapshot.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, wrongSnapshot.GetProperty("verifiedSubject").ValueKind);
        _clock.Now = Epoch.AddMinutes(3);
        var (_, expiredResult) = await JsonAsync(Vcdm20PresentationEndpoints.Verify(
            Request(challenge, presentation, snapshot), store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", expiredResult.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ChallengeRejectsInvalidInputsWithoutAllocation()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        foreach (var request in new[]
        {
            new IssueVcdm20PresentationChallengeRequest { Audience = "http://evil.example", TrustedIssuerDid = _issuer.Did },
            new IssueVcdm20PresentationChallengeRequest { Audience = Audience, TrustedIssuerDid = "did:key:fake" },
            new IssueVcdm20PresentationChallengeRequest { Audience = Audience, TrustedIssuerDid = _issuer.Did, LifetimeSeconds = 301 }
        })
        {
            var (status, _) = await JsonAsync(Vcdm20PresentationEndpoints.Issue(
                request, store, _tenant)).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, status);
        }
    }

    [Fact]
    public async Task RouteEndpointsRequireCredentialVerifyAndDoNotPermitAnonymous()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        var routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>();
        foreach (string path in new[]
        {
            "/api/v1/credentials/vcdm20/presentation-challenge",
            "/api/v1/credentials/vcdm20/verify-presentation"
        })
        {
            var route = Assert.Single(routes, e => e.RoutePattern.RawText == path);
            Assert.Equal("POST", Assert.Single(route.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(), p => p.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
        }
    }

    private (PresentationChallenge Challenge, string Presentation, string Snapshot) CreatePresentation(
        InMemoryPresentationChallengeStore store)
    {
        var challenge = store.Issue(_tenant.Id, Audience, _issuer.Did);
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, role = "member" }));
        string credential = Vcdm20JoseCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Context, subject.RootElement,
            _issuer.Seed, Epoch.AddMinutes(-1), Epoch.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            signedRequest, _verifier.Did, Audience, credential, CredentialType,
            Context, _holder.Did, _holder.Seed, _clock);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, _clock.GetUtcNow(), _clock);
        return (challenge, presentation, snapshot);
    }

    private static string EnclosedCredential(string presentation)
    {
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        string uri = payload.RootElement.GetProperty("verifiableCredential")[0].GetProperty("id").GetString()!;
        return uri["data:application/vc+jwt,".Length..];
    }

    private static VerifyVcdm20PresentationRequest Request(
        PresentationChallenge challenge, string presentation, string snapshot) => new()
    {
        Audience = Audience, Nonce = challenge.Nonce, Presentation = presentation,
        RevocationSnapshot = snapshot, ExpectedCredentialType = CredentialType,
        SubjectContextUri = Context
    };

    private static async Task<(int Status, JsonElement Json)> JsonAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await result.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var doc = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, doc.RootElement.Clone());
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed class Tenant : ITenantContext
    {
        public Guid Id { get; } = Guid.NewGuid();
        public Guid GetCurrentTenantId() => Id;
    }

    private sealed class Clock(DateTimeOffset time) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = time;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
