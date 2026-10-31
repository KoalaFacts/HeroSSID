using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class Vcdm20VerifierDenylistHttpTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType = "MembershipCredential";

    [Fact]
    public async Task ExplicitRoutesMustRequireCredentialVerifyAndPost()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        RouteEndpoint[] endpoints = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>().ToArray();
        foreach (string path in new[]
        {
            "/api/v1/credentials/vcdm20/verify-trusted-issuers-with-denylist",
            "/api/v1/credentials/vcdm20/verify-trusted-issuers-with-denylist-and-status"
        })
        {
            var endpoint = Assert.Single(endpoints, e => e.RoutePattern.RawText == path);
            Assert.Contains(endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static data => data.Policy == "credential:verify");
            Assert.Null(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    [Fact]
    public async Task GenuineHistoricalAndCurrentIssuerCredentialsCanBeIndependentlyDenied()
    {
        var fixture = Create();
        foreach (string token in new[] { fixture.OldToken, fixture.NewToken })
        {
            var denied = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
                Request(fixture, token) with { DeniedCredentialSha256 = [Digest(token)] },
                new FixedClock(Now))).ConfigureAwait(true);
            AssertBlocked(denied, "DeniedByVerifier");
        }
    }

    [Fact]
    public async Task ValidCredentialWithoutLocalDenialReleasesOnlyAuthenticatedClaims()
    {
        var fixture = Create();
        var accepted = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
            Request(fixture, fixture.OldToken), new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, accepted.Status);
        Assert.Equal("SignedButStatusUnchecked", accepted.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.OldDid, accepted.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", accepted.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());
    }

    [Fact]
    public async Task IssuerSignedCleanStatusNeverOverridesIndependentDenial()
    {
        var fixture = Create();
        string clean = Vcdm20RevocationSnapshot.Create(
            fixture.NewDid, [], fixture.NewSeed, Now.AddSeconds(-5), new FixedClock(Now));
        string revoked = Vcdm20RevocationSnapshot.Create(
            fixture.NewDid, [fixture.NewToken], fixture.NewSeed,
            Now.AddSeconds(-5), new FixedClock(Now));
        string foreign = Vcdm20RevocationSnapshot.Create(
            fixture.OldDid, [], fixture.OldSeed, Now.AddSeconds(-5), new FixedClock(Now));
        var request = Request(fixture, fixture.NewToken) with
        {
            DeniedCredentialSha256 = [Digest(fixture.NewToken)], RevocationSnapshot = clean
        };
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint
            .VerifyWithDenylistAndStatus(request, new FixedClock(Now))).ConfigureAwait(true), "DeniedByVerifier");
        var accepted = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
            request with { DeniedCredentialSha256 = [] }, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.NewDid, accepted.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", accepted.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
            request with { DeniedCredentialSha256 = [], RevocationSnapshot = revoked },
            new FixedClock(Now))).ConfigureAwait(true), "IssuerReportedRevoked");
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
            request with { RevocationSnapshot = foreign },
            new FixedClock(Now))).ConfigureAwait(true), "Invalid");
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
            request, new FixedClock(Now.AddSeconds(61)))).ConfigureAwait(true), "Invalid");
    }

    [Fact]
    public async Task DenialFingerprintCannotAuthenticateForgedUntrustedOrWrongHolderJwt()
    {
        var fixture = Create();
        var (outsiderSeed, outsiderDid) = NewKey();
        string outsider = Vcdm20JoseCredential.Create(
            outsiderDid, fixture.HolderDid, CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = fixture.HolderDid, role = "administrator" }),
            outsiderSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
            Request(fixture, outsider) with { DeniedCredentialSha256 = [Digest(outsider)] },
            new FixedClock(Now))).ConfigureAwait(true), "Invalid");
        string[] parts = fixture.NewToken.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(fixture.NewToken)
            .Replace("member", "administrator", StringComparison.Ordinal));
        string tampered = string.Join('.', parts);
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
            Request(fixture, tampered) with { DeniedCredentialSha256 = [Digest(tampered)] },
            new FixedClock(Now))).ConfigureAwait(true), "Invalid");
        AssertBlocked(await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
            Request(fixture, fixture.NewToken) with
            {
                ExpectedHolderDid = fixture.OldDid,
                DeniedCredentialSha256 = [Digest(fixture.NewToken)]
            }, new FixedClock(Now))).ConfigureAwait(true), "Invalid");
    }

    [Fact]
    public async Task InvalidOrMissingDenialPolicyFailsRequestBeforeAnyClaimDisclosure()
    {
        var fixture = Create();
        var request = Request(fixture, fixture.NewToken);
        string digest = Digest(fixture.NewToken);
        foreach (var malformed in new[]
        {
            request with { DeniedCredentialSha256 = null },
            request with { DeniedCredentialSha256 = [digest, digest] },
            request with { DeniedCredentialSha256 = [digest.ToUpperInvariant()] },
            request with { DeniedCredentialSha256 = ["not-a-digest"] },
            request with { DeniedCredentialSha256 = Enumerable.Repeat(digest, 257).ToArray() },
            request with { RevocationSnapshot = "do-not-ignore-issuer-status" }
        })
        {
            var result = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylist(
                malformed, new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
        }
        var noStatus = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
            request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, noStatus.Status);
    }

    [Fact]
    public async Task LegacyRoutesMustRejectJsonPolicyRatherThanIgnoreIt()
    {
        var fixture = Create();
        string body = JsonSerializer.Serialize(new
        {
            Credential = fixture.NewToken,
            TrustedIssuerDids = new[] { fixture.NewDid },
            DeniedCredentialSha256 = new[] { Digest(fixture.NewToken) },
            ExpectedHolderDid = fixture.HolderDid,
            ExpectedCredentialType = CredentialType,
            SubjectContextUri = Vocabulary
        });
        var request = JsonSerializer.Deserialize<VerifyVcdm20TrustedIssuersRequest>(body);
        Assert.NotNull(request);
        var response = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
            request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
    }

    private static VerifyVcdm20TrustedIssuersRequest Request(Fixture fixture, string token) => new()
    {
        Credential = token,
        TrustedIssuerDids = [fixture.OldDid, fixture.NewDid],
        DeniedCredentialSha256 = [],
        ExpectedHolderDid = fixture.HolderDid,
        ExpectedCredentialType = CredentialType,
        SubjectContextUri = Vocabulary
    };

    private static Fixture Create()
    {
        var (oldSeed, oldDid) = NewKey();
        var (newSeed, newDid) = NewKey();
        var (_, holderDid) = NewKey();
        JsonElement claims = JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" });
        string oldJwt = Vcdm20JoseCredential.Create(oldDid, holderDid,
            CredentialType, Vocabulary, claims, oldSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        string newJwt = Vcdm20JoseCredential.Create(newDid, holderDid,
            CredentialType, Vocabulary, claims, newSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        return new Fixture(oldDid, newDid, holderDid, oldSeed, newSeed, oldJwt, newJwt);
    }

    private static void AssertBlocked((int Status, JsonElement Body) response, string expected)
    {
        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal(expected, response.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedSubject").ValueKind);
    }

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await result.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var payload = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, payload.RootElement.Clone());
    }

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

    private static (byte[] Seed, string Did) NewKey()
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

    private sealed record Fixture(string OldDid, string NewDid, string HolderDid,
        byte[] OldSeed, byte[] NewSeed, string OldToken, string NewToken);
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
