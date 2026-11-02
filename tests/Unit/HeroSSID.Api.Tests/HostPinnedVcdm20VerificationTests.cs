using System.Security.Cryptography;
using System.Text;
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
    private static readonly JsonSerializerOptions HttpJsonOptions = new(JsonSerializerDefaults.Web);

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

        foreach (string path in new[]
        {
            "/api/v1/credentials/vcdm20/verify-host-pinned",
            "/api/v1/credentials/vcdm20/verify-host-pinned-with-status"
        })
        {
            var route = Assert.Single(routes,
                endpoint => endpoint.RoutePattern.RawText == path);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static policy => policy.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata
                .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
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
            HttpJsonOptions));
    }

    [Fact]
    public async Task OperatorDeniedAuthenticVc2NeverReleasesIssuerOrSubject()
    {
        var fixture = Create();
        var request = new VerifyHostPinnedVcdm20Request
        {
            PolicyId = "membership-v1", Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid
        };
        var deniedConfig = Configuration(fixture.Tenant, fixture.IssuerDid);
        deniedConfig["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] =
            Digest(fixture.ValidJwt);
        var deniedRegistry = new HostPinnedVcdm20IssuerRegistry(deniedConfig);
        var response = await ExecuteAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, deniedRegistry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);

        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal("DeniedByVerifier", response.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedSubject").ValueKind);

        // A different exact JWT digest cannot deny this authentic credential.
        var unrelatedConfig = Configuration(fixture.Tenant, fixture.IssuerDid);
        unrelatedConfig["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] =
            Digest(fixture.RogueJwt);
        var unrelatedRegistry = new HostPinnedVcdm20IssuerRegistry(unrelatedConfig);
        var accepted = await ExecuteAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, unrelatedRegistry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", accepted.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.IssuerDid,
            accepted.Body.GetProperty("verifiedIssuerDid").GetString());

        // A forged credential cannot become authentic merely by matching a denial hash.
        var forged = Tamper(fixture.ValidJwt);
        var forgedConfig = Configuration(fixture.Tenant, fixture.IssuerDid);
        forgedConfig["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] = Digest(forged);
        await AssertInvalidAsync(HostPinnedVcdm20TrustedIssuerVerificationEndpoint.Verify(
            request with { Credential = forged },
            new HostPinnedVcdm20IssuerRegistry(forgedConfig),
            new FixedTenant(fixture.Tenant), new FixedClock(Now))).ConfigureAwait(true);
    }

    [Fact]
    public async Task HostPinnedStatusRequiresAuthenticCurrentSameIssuerSnapshot()
    {
        var fixture = Create();
        var registry = new HostPinnedVcdm20IssuerRegistry(Configuration(
            fixture.Tenant, fixture.IssuerDid));
        string clean = Vcdm20RevocationSnapshot.Create(
            fixture.IssuerDid, [], fixture.IssuerSeed, Now, new FixedClock(Now));
        var request = new VerifyHostPinnedVcdm20WithStatusRequest
        {
            PolicyId = "membership-v1",
            Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid,
            RevocationSnapshot = clean
        };

        var verified = await ExecuteAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request, registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, verified.Status);
        Assert.Equal("SignedNotListed", verified.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.IssuerDid,
            verified.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member",
            verified.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());

        string unrelatedIssuerSnapshot = Vcdm20RevocationSnapshot.Create(
            fixture.RogueDid, [], fixture.RogueSeed, Now, new FixedClock(Now));
        await AssertInvalidAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request with { RevocationSnapshot = unrelatedIssuerSnapshot },
                registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        await AssertInvalidAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request with { Credential = Tamper(fixture.ValidJwt) },
                registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        await AssertInvalidAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request, registry, new FixedTenant(Guid.NewGuid()), new FixedClock(Now)))
            .ConfigureAwait(true);
        await AssertInvalidAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request, registry, new FixedTenant(fixture.Tenant),
                new FixedClock(Now.AddSeconds(61))))
            .ConfigureAwait(true);

        var missing = await ExecuteAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request with { RevocationSnapshot = null },
                registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missing.Status);
    }

    [Fact]
    public async Task IssuerRevocationAndOperatorDenialNeverReleaseHostPinnedClaims()
    {
        var fixture = Create();
        var registry = new HostPinnedVcdm20IssuerRegistry(Configuration(
            fixture.Tenant, fixture.IssuerDid));
        string revoked = Vcdm20RevocationSnapshot.Create(
            fixture.IssuerDid, [fixture.ValidJwt], fixture.IssuerSeed, Now,
            new FixedClock(Now));
        string clean = Vcdm20RevocationSnapshot.Create(
            fixture.IssuerDid, [], fixture.IssuerSeed, Now, new FixedClock(Now));
        var request = new VerifyHostPinnedVcdm20WithStatusRequest
        {
            PolicyId = "membership-v1", Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid, RevocationSnapshot = revoked
        };
        var issuerDenied = await ExecuteAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request, registry, new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal("IssuerReportedRevoked",
            issuerDenied.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            issuerDenied.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null,
            issuerDenied.Body.GetProperty("verifiedSubject").ValueKind);

        var config = Configuration(fixture.Tenant, fixture.IssuerDid);
        config["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] =
            Digest(fixture.ValidJwt);
        var operatorDenied = await ExecuteAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request with { RevocationSnapshot = clean },
                new HostPinnedVcdm20IssuerRegistry(config),
                new FixedTenant(fixture.Tenant), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal("DeniedByVerifier",
            operatorDenied.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            operatorDenied.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null,
            operatorDenied.Body.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public void StatusRequestCannotSupplyOrOverrideOperatorTrust()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<VerifyHostPinnedVcdm20WithStatusRequest>(
                "{\"policyId\":\"membership-v1\",\"credential\":\"x.y.z\"," +
                "\"revocationSnapshot\":\"signed.status.jwt\"," +
                "\"trustedIssuerDids\":[\"did:key:attacker\"]}",
                HttpJsonOptions));
    }

    [Fact]
    public void MalformedDuplicateOrOversizedOperatorDenialPolicyFailsStartup()
    {
        var fixture = Create();
        string digest = Digest(fixture.ValidJwt);
        var invalid = Configuration(fixture.Tenant, fixture.IssuerDid);
        invalid["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] =
            digest.ToUpperInvariant();
        Assert.Throws<InvalidOperationException>(
            () => new HostPinnedVcdm20IssuerRegistry(invalid));

        var duplicated = Configuration(fixture.Tenant, fixture.IssuerDid);
        duplicated["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0"] = digest;
        duplicated["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:1"] = digest;
        Assert.Throws<InvalidOperationException>(
            () => new HostPinnedVcdm20IssuerRegistry(duplicated));

        var nested = Configuration(fixture.Tenant, fixture.IssuerDid);
        nested["Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0:Nested"] = digest;
        Assert.Throws<InvalidOperationException>(
            () => new HostPinnedVcdm20IssuerRegistry(nested));

        var oversized = Configuration(fixture.Tenant, fixture.IssuerDid);
        for (int i = 0; i < 257; i++)
        {
            oversized[$"Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:{i}"] =
                i.ToString("x64", System.Globalization.CultureInfo.InvariantCulture);
        }

        Assert.Throws<InvalidOperationException>(
            () => new HostPinnedVcdm20IssuerRegistry(oversized));
    }

    [Fact]
    public async Task HostIncidentCutoffRejectsStillFreshPreIncidentIssuerStatusWithoutDisclosure()
    {
        var fixture = Create();
        var config = Configuration(fixture.Tenant, fixture.IssuerDid);
        config["Vcdm20VerifierTrust:Policies:0:MinimumStatusObservedAtUtc"] =
            Now.AddSeconds(1).ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        var registry = new HostPinnedVcdm20IssuerRegistry(config);
        string beforeIncident = Vcdm20RevocationSnapshot.Create(
            fixture.IssuerDid, [], fixture.IssuerSeed, Now, new FixedClock(Now));
        var request = new VerifyHostPinnedVcdm20WithStatusRequest
        {
            PolicyId = "membership-v1", Credential = fixture.ValidJwt,
            ExpectedHolderDid = fixture.HolderDid, RevocationSnapshot = beforeIncident
        };

        // The signed pre-incident snapshot remains inside its normal 60-second
        // validity window; only the independent host cutoff must reject it.
        await AssertInvalidAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request, registry, new FixedTenant(fixture.Tenant),
                new FixedClock(Now.AddSeconds(3)))).ConfigureAwait(true);

        string afterIncident = Vcdm20RevocationSnapshot.Create(
            fixture.IssuerDid, [], fixture.IssuerSeed, Now.AddSeconds(2),
            new FixedClock(Now.AddSeconds(2)));
        var accepted = await ExecuteAsync(
            HostPinnedVcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
                request with { RevocationSnapshot = afterIncident }, registry,
                new FixedTenant(fixture.Tenant), new FixedClock(Now.AddSeconds(3))))
            .ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.IssuerDid,
            accepted.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member",
            accepted.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());
    }

    [Fact]
    public void MalformedOrNonUtcHostStatusObservationCutoffRejectsEntireStartupPolicy()
    {
        var fixture = Create();
        foreach (string cutoff in new[]
        {
            "invalid",
            Now.ToOffset(TimeSpan.FromHours(2)).ToString("O",
                System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.FromUnixTimeSeconds(-1).ToString("O",
                System.Globalization.CultureInfo.InvariantCulture)
        })
        {
            var invalid = Configuration(fixture.Tenant, fixture.IssuerDid);
            invalid["Vcdm20VerifierTrust:Policies:0:MinimumStatusObservedAtUtc"] = cutoff;
            Assert.Throws<InvalidOperationException>(
                () => new HostPinnedVcdm20IssuerRegistry(invalid));
        }
    }

    [Fact]
    public void NestedIncidentCutoffConfigurationCannotBeSilentlyIgnored()
    {
        var fixture = Create();
        var nested = Configuration(fixture.Tenant, fixture.IssuerDid);
        nested["Vcdm20VerifierTrust:Policies:0:MinimumStatusObservedAtUtc:Nested"] =
            Now.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        Assert.Throws<InvalidOperationException>(
            () => new HostPinnedVcdm20IssuerRegistry(nested));
    }

    [Fact]
    public void HttpStatusCallerCannotInjectItsOwnObservationCutoff()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<VerifyHostPinnedVcdm20WithStatusRequest>(
                """
                {"policyId":"membership-v1","credential":"x.y.z","revocationSnapshot":"signed.status.jwt","minimumStatusObservedAtUtc":"1900-01-01T00:00:00Z"}
                """,
                HttpJsonOptions));
    }

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

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
        return new Fixture(tenant, issuerDid, holderDid, valid, rogue,
            issuerSeed, rogueSeed, rogueDid);
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
        string ValidJwt, string RogueJwt, byte[] IssuerSeed, byte[] RogueSeed,
        string RogueDid);

    private sealed class FixedTenant(Guid tenant) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenant;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
