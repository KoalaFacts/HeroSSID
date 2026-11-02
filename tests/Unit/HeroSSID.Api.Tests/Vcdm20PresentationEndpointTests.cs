using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class Vcdm20PresentationEndpointTests
{
    private const string Audience = "https://verifier.example/present";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/context/membership/v1");
    private static readonly DateTimeOffset Epoch = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions HttpJsonOptions = new(JsonSerializerDefaults.Web);
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
            .Replace("https://verifier.example/present", "https://attacker.example/present", StringComparison.Ordinal));
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


    [Fact]
    public async Task HostPinnedPresentationAuthenticatesIssuerHolderAndSpendsOnlyAcceptedChallenge()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var request = HostRequest(challenge, presentation, snapshot);
        var foreign = NewIdentity();
        var (_, rejected) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, Registry(foreign.Did), store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);

        // An unapproved issuer cannot cause disclosure or spend a legitimate
        // verifier challenge. Only the server-pinned genuine issuer is accepted.
        var registry = Registry(_issuer.Did);
        var (_, accepted) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.GetProperty("status").GetString());
        Assert.Equal("member", accepted.GetProperty("verifiedSubject").GetProperty("role").GetString());
        var (_, replay) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", replay.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replay.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task ForgedHolderAndCrossTenantCannotConsumeAnAuthenticHostPinnedProof()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var registry = Registry(_issuer.Did);
        var request = HostRequest(challenge, presentation, snapshot);
        string[] parts = presentation.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(presentation)
            .Replace(Audience, "https://attacker.example/present", StringComparison.Ordinal));
        string forgedHolder = string.Join('.', parts);

        var (_, forged) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request with { Presentation = forgedHolder },
            registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", forged.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, forged.GetProperty("verifiedSubject").ValueKind);

        var (_, crossTenant) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, registry, store, new Tenant(), _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", crossTenant.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, crossTenant.GetProperty("verifiedSubject").ValueKind);

        // Neither rejected proof spends the original verifier's challenge.
        var (_, valid) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", valid.GetProperty("status").GetString());
        Assert.Equal("member", valid.GetProperty("verifiedSubject").GetProperty("role").GetString());
    }

    [Fact]
    public async Task HostOwnedDenialAndVocabularyRefuseAuthenticHolderProofWithoutClaims()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, snapshot) = CreatePresentation(store);
        var request = HostRequest(challenge, presentation, snapshot);
        var wrongVocabulary = Registry(_issuer.Did, credentialType: "AdministratorCredential");
        var (_, wrong) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, wrongVocabulary, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", wrong.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, wrong.GetProperty("verifiedSubject").ValueKind);

        // Denial applies to the exact ORIGINAL issuer-signed JWT enclosed
        // inside the holder-signed VP; callers cannot substitute its digest.
        string original = EnclosedCredential(presentation);
        var denied = Registry(_issuer.Did, deniedHash: Digest(original));
        var (_, refused) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, denied, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("DeniedByVerifier", refused.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, refused.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task HostOwnedIncidentCutoffRejectsAuthenticOldIssuerStatusAndPreventsReplay()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var (challenge, presentation, _) = CreatePresentation(store);
        string old = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, Epoch.AddSeconds(-25), _clock);
        var request = HostRequest(challenge, presentation, old);
        var registry = Registry(_issuer.Did, cutoff: Epoch.AddSeconds(-10));
        var (_, rejected) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request, registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);

        string fresh = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, Epoch, _clock);
        var (_, replay) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            request with { RevocationSnapshot = fresh },
            registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", replay.GetProperty("status").GetString());

        var (newChallenge, newPresentation, newSnapshot) = CreatePresentation(store);
        var (_, accepted) = await JsonAsync(Vcdm20PresentationEndpoints.VerifyHostPinned(
            HostRequest(newChallenge, newPresentation, newSnapshot),
            registry, store, _tenant, _clock)).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.GetProperty("status").GetString());
        Assert.Equal("member", accepted.GetProperty("verifiedSubject").GetProperty("role").GetString());
    }

    [Fact]
    public void HostPinnedHolderRouteIsScopedAndUntrustedPolicyFieldsFailBinding()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        using var app = builder.Build();
        app.MapCredentialEndpoints();
        var route = Assert.Single(((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>(),
            endpoint => endpoint.RoutePattern.RawText ==
                "/api/v1/credentials/vcdm20/verify-host-pinned-presentation");
        Assert.Equal("POST", Assert.Single(route.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            p => p.Policy == "credential:verify");
        Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<VerifyHostPinnedVcdm20PresentationRequest>(
            "{\"policyId\":\"membership-v1\",\"trustedIssuerDids\":[\"did:key:attacker\"]}",
            HttpJsonOptions));
    }

    private HostPinnedVcdm20IssuerRegistry Registry(string issuerDid, string? deniedHash = null,
        DateTimeOffset? cutoff = null, string credentialType = CredentialType)
    {
        var entries = new Dictionary<string, string?>
        {
            ["Vcdm20VerifierTrust:Policies:0:TenantId"] = _tenant.Id.ToString("D", CultureInfo.InvariantCulture),
            ["Vcdm20VerifierTrust:Policies:0:PolicyId"] = "membership-v1",
            ["Vcdm20VerifierTrust:Policies:0:CredentialType"] = credentialType,
            ["Vcdm20VerifierTrust:Policies:0:SubjectContextUri"] = Context.AbsoluteUri,
            ["Vcdm20VerifierTrust:Policies:0:TrustedIssuerDids:0"] = issuerDid
        };
        if (deniedHash is not null)
        {
            entries["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] = deniedHash;
        }
        if (cutoff is DateTimeOffset instant)
        {
            entries["Vcdm20VerifierTrust:Policies:0:MinimumStatusObservedAtUtc"] =
                instant.ToString("O", CultureInfo.InvariantCulture);
        }

        return new HostPinnedVcdm20IssuerRegistry(
            new ConfigurationBuilder().AddInMemoryCollection(entries).Build());
    }

    private static VerifyHostPinnedVcdm20PresentationRequest HostRequest(
        PresentationChallenge challenge, string presentation, string snapshot) => new()
    {
        PolicyId = "membership-v1", Audience = Audience, Nonce = challenge.Nonce,
        Presentation = presentation, RevocationSnapshot = snapshot
    };

    private static string Digest(string credential) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));

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
