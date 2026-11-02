using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class HostPinnedVcdm20VerificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 3, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string Type = "MembershipCredential";

    [Fact]
    public async Task AuthenticatedHostPinnedIssuerVerificationRouteIsAvailable()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing"
        });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();

        RouteEndpoint[] routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints)
            .OfType<RouteEndpoint>().ToArray();

        var route = Assert.Single(routes,
            endpoint => endpoint.RoutePattern.RawText ==
                "/api/v1/credentials/vcdm20/verify-host-pinned");
        Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            static policy => policy.Policy == "credential:verify");
        Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal("POST", Assert.Single(route.Metadata
            .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
    }

    [Fact]
    public async Task HostApprovedOriginalIssuerReleasesOnlyGenuinelySignedSubject()
    {
        var fixture = Create();
        var registry = new HostPinnedVcdm20IssuerRegistry(Configuration(
            fixture.Tenant, fixture.IssuerDid));
        var request = new VerifyHostPinnedVcdm20Request
        {
            PolicyId = "membership-v1", Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid
        };
        var result = await ExecuteAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);

        Assert.Equal(StatusCodes.Status200OK, result.Status);
        Assert.Equal("SignedButStatusUnchecked", result.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.IssuerDid, result.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", result.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());

        foreach (string credential in new[] { fixture.RogueJwt, Tamper(fixture.ValidJwt) })
        {
            await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
                request with { Credential = credential }, registry,
                new FixedTenant(fixture.Tenant), new FixedClock(Now))).ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task MissingForeignOrDifferentlyTypedHostPolicyNeverReleasesClaims()
    {
        var fixture = Create();
        var registry = new HostPinnedVcdm20IssuerRegistry(Configuration(
            fixture.Tenant, fixture.IssuerDid));
        var request = new VerifyHostPinnedVcdm20Request
        {
            PolicyId = "membership-v1", Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid
        };
        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, registry, new FixedTenant(Guid.NewGuid()), new FixedClock(Now)))
            .ConfigureAwait(true);
        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            new VerifyHostPinnedVcdm20Request
            {
                PolicyId = "other-policy", Credential = fixture.ValidJwt,
                ExpectedHolderDid = fixture.HolderDid
            }, registry, new FixedTenant(fixture.Tenant), new FixedClock(Now))).ConfigureAwait(true);

        var wrongType = Configuration(fixture.Tenant, fixture.IssuerDid);
        wrongType["Vcdm20VerifierTrust:Policies:0:CredentialType"] = "AdministratorCredential";
        var wrongRegistry = new HostPinnedVcdm20IssuerRegistry(wrongType);
        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, wrongRegistry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);

        var wrongContext = Configuration(fixture.Tenant, fixture.IssuerDid);
        wrongContext["Vcdm20VerifierTrust:Policies:0:SubjectContextUri"] =
            "https://attacker.example/contexts/membership/v1";
        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, new HostPinnedVcdm20IssuerRegistry(wrongContext),
            new FixedTenant(fixture.Tenant), new FixedClock(Now))).ConfigureAwait(true);

        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            new VerifyHostPinnedVcdm20Request
            {
                PolicyId = "membership-v1", Credential = fixture.ValidJwt,
                ExpectedHolderDid = fixture.IssuerDid
            }, registry, new FixedTenant(fixture.Tenant), new FixedClock(Now))).ConfigureAwait(true);
    }

    [Fact]
    public void InvalidOrDuplicateOperatorIssuerEnrollmentFailsBeforeServing()
    {
        var fixture = Create();
        var badDid = Configuration(fixture.Tenant, fixture.IssuerDid);
        badDid["Vcdm20VerifierTrust:Policies:0:TrustedIssuerDids:0"] = "did:key:invalid";
        Assert.Throws<InvalidOperationException>(() => new HostPinnedVcdm20IssuerRegistry(badDid));

        var duplicateDid = Configuration(fixture.Tenant, fixture.IssuerDid);
        duplicateDid["Vcdm20VerifierTrust:Policies:0:TrustedIssuerDids:1"] = fixture.IssuerDid;
        Assert.Throws<InvalidOperationException>(() => new HostPinnedVcdm20IssuerRegistry(duplicateDid));

        var duplicatePolicy = Configuration(fixture.Tenant, fixture.IssuerDid);
        foreach (var pair in ConfigurationEntries(fixture.Tenant, fixture.IssuerDid))
        {
            duplicatePolicy["Vcdm20VerifierTrust:Policies:1" +
                pair.Key["Vcdm20VerifierTrust:Policies:0".Length..]] = pair.Value;
        }

        Assert.Throws<InvalidOperationException>(() => new HostPinnedVcdm20IssuerRegistry(duplicatePolicy));

        var wrongContext = Configuration(fixture.Tenant, fixture.IssuerDid);
        wrongContext["Vcdm20VerifierTrust:Policies:0:SubjectContextUri"] = "http://issuer.example/context";
        Assert.Throws<InvalidOperationException>(() => new HostPinnedVcdm20IssuerRegistry(wrongContext));
    }

    [Fact]
    public void CallerCannotInjectOrReplaceHostTrustByExtraJsonFields()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<VerifyHostPinnedVcdm20Request>(
            "{\"policyId\":\"membership-v1\",\"credential\":\"x.y.z\",\"trustedIssuerDids\":[\"did:key:attacker\"]}",
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }));
    }

    private static Dictionary<string, string?> ConfigurationEntries(Guid tenant, string issuer) => new()
    {
        ["Vcdm20VerifierTrust:Policies:0:TenantId"] = tenant.ToString("D"),
        ["Vcdm20VerifierTrust:Policies:0:PolicyId"] = "membership-v1",
        ["Vcdm20VerifierTrust:Policies:0:CredentialType"] = Type,
        ["Vcdm20VerifierTrust:Policies:0:SubjectContextUri"] = Vocabulary.AbsoluteUri,
        ["Vcdm20VerifierTrust:Policies:0:TrustedIssuerDids:0"] = issuer
    };

    private static IConfigurationRoot Configuration(Guid tenant, string issuer) =>
        new ConfigurationBuilder().AddInMemoryCollection(ConfigurationEntries(tenant, issuer)).Build();

    private static Fixture Create()
    {
        Guid tenant = Guid.NewGuid();
        var (issuerSeed, issuerDid) = NewKey();
        var (rogueSeed, rogueDid) = NewKey();
        var (_, holderDid) = NewKey();
        JsonElement subject = JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" });
        string valid = Vcdm20JoseCredential.Create(issuerDid, holderDid, Type, Vocabulary,
            subject, issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        string rogue = Vcdm20JoseCredential.Create(rogueDid, holderDid, Type, Vocabulary,
            subject, rogueSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        return new Fixture(tenant, issuerDid, holderDid, valid, rogue);
    }

    private static string Tamper(string original)
    {
        string[] parts = original.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(original)
            .Replace("member", "admin", StringComparison.Ordinal));
        return string.Join('.', parts);
    }

    private static (byte[] Seed, string Did) NewKey()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }

    private static async Task AssertInvalidAsync(IResult result)
    {
        var response = await ExecuteAsync(result).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal("Invalid", response.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedSubject").ValueKind);
    }

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult response)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await response.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var document = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, document.RootElement.Clone());
    }

    private sealed record Fixture(Guid Tenant, string IssuerDid, string HolderDid,
        string ValidJwt, string RogueJwt);

    private sealed class FixedTenant(Guid tenant) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenant;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
