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

public sealed class Vcdm20TrustedIssuerVerificationEndpointTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");

    [Fact]
    public async Task TwoIndependentlyEnrolledIssuersVerifyAndReturnActualAuthenticatedSigner()
    {
        var fixture = Create();
        foreach (var (token, expectedSigner) in new[]
        {
            (fixture.OldToken, fixture.OldDid), (fixture.NewToken, fixture.NewDid)
        })
        {
            var result = await ExecuteAsync(
                Vcdm20TrustedIssuerVerificationEndpoint.Verify(
                    Request(fixture, token), new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status200OK, result.Status);
            Assert.Equal("SignedButStatusUnchecked", result.Body.GetProperty("status").GetString());
            Assert.Equal(expectedSigner, result.Body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member", result.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());
        }
    }

    [Fact]
    public async Task RetirementAndForgeryCannotReleaseSignerOrClaims()
    {
        var fixture = Create();
        var retired = Request(fixture, fixture.OldToken, [fixture.NewDid]);
        await AssertDeniedAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
            retired, new FixedClock(Now))).ConfigureAwait(true);

        var parts = fixture.NewToken.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(fixture.NewToken)
                .Replace("member", "administrator", StringComparison.Ordinal));
        await AssertDeniedAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
            Request(fixture, string.Join('.', parts)), new FixedClock(Now))).ConfigureAwait(true);

        var wrongHolder = Request(fixture, fixture.NewToken) with
        {
            ExpectedHolderDid = fixture.OldDid
        };
        await AssertDeniedAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
            wrongHolder, new FixedClock(Now))).ConfigureAwait(true);
        var wrongVocabulary = Request(fixture, fixture.NewToken) with
        {
            SubjectContextUri = new Uri("https://attacker.example/contexts/membership/v1")
        };
        await AssertDeniedAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
            wrongVocabulary, new FixedClock(Now))).ConfigureAwait(true);
    }

    [Fact]
    public async Task StatusRequiresAuthenticatedCredentialSignerRatherThanAnyEnrolledIssuer()
    {
        var fixture = Create();
        string newClean = Vcdm20RevocationSnapshot.Create(
            fixture.NewDid, [], fixture.NewSeed, Now.AddSeconds(-5), new FixedClock(Now));
        var verified = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = newClean },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, verified.Status);
        Assert.Equal("SignedNotListed", verified.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.NewDid, verified.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", verified.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());

        // The old key remains enrolled but must not vouch for the new issuer's token.
        string oldClean = Vcdm20RevocationSnapshot.Create(
            fixture.OldDid, [], fixture.OldSeed, Now.AddSeconds(-5), new FixedClock(Now));
        await AssertDeniedAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = oldClean },
            new FixedClock(Now))).ConfigureAwait(true);

        string revoked = Vcdm20RevocationSnapshot.Create(
            fixture.NewDid, [fixture.NewToken], fixture.NewSeed,
            Now.AddSeconds(-5), new FixedClock(Now));
        var denied = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = revoked },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("Revoked", denied.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedSubject").ValueKind);
        Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedIssuerDid").ValueKind);
    }

    [Fact]
    public async Task UnboundedAmbiguousAndMissingPolicyIsBadRequest()
    {
        var fixture = Create();
        string[][] rejected =
        [
            [], [fixture.OldDid, fixture.OldDid],
            [fixture.OldDid, "did:key:invalid"],
            Enumerable.Repeat(fixture.NewDid, 17).ToArray()
        ];
        foreach (var issuers in rejected)
        {
            var result = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.Verify(
                Request(fixture, fixture.NewToken, issuers), new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
        }

        var missingStatus = await ExecuteAsync(Vcdm20TrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken), new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missingStatus.Status);
    }

    [Fact]
    public async Task NewHttpRoutesRequireCredentialVerifyScopeAndPost()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        var endpoints = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>().ToArray();
        foreach (string routeName in new[]
        {
            "/api/v1/credentials/vcdm20/verify-trusted-issuers",
            "/api/v1/credentials/vcdm20/verify-trusted-issuers-with-status"
        })
        {
            var route = Assert.Single(endpoints, e => e.RoutePattern.RawText == routeName);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(), static policy =>
                policy.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    private static async Task AssertDeniedAsync(IResult input)
    {
        var result = await ExecuteAsync(input).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, result.Status);
        Assert.Equal("Invalid", result.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, result.Body.GetProperty("verifiedSubject").ValueKind);
        Assert.Equal(JsonValueKind.Null, result.Body.GetProperty("verifiedIssuerDid").ValueKind);
    }

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult response)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await response.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var payload = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, payload.RootElement.Clone());
    }

    private static VerifyVcdm20TrustedIssuersRequest Request(
        Fixture fixture, string token, string[]? allowed = null) => new()
    {
        Credential = token,
        TrustedIssuerDids = allowed ?? [fixture.OldDid, fixture.NewDid],
        ExpectedHolderDid = fixture.HolderDid,
        ExpectedCredentialType = "MembershipCredential",
        SubjectContextUri = Vocabulary
    };

    private static Fixture Create()
    {
        var (oldSeed, oldDid) = NewKey();
        var (newSeed, newDid) = NewKey();
        var (_, holderDid) = NewKey();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        string oldJwt = Vcdm20JoseCredential.Create(
            oldDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            oldSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        string newJwt = Vcdm20JoseCredential.Create(
            newDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            newSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        return new Fixture(oldDid, newDid, holderDid, oldSeed, newSeed, oldJwt, newJwt);
    }

    private static (byte[] Seed, string Did) NewKey()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }

    private sealed record Fixture(
        string OldDid, string NewDid, string HolderDid, byte[] OldSeed,
        byte[] NewSeed, string OldToken, string NewToken);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
