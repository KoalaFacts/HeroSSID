using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class JwtVcJsonTrustedIssuerVerificationEndpointTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 10, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";

    [Fact]
    public async Task PreviousAndCurrentTrustedIssuersReturnOnlyTheirRealAuthenticatedSigner()
    {
        var fixture = Create();
        foreach (var (credential, issuer) in new[]
        {
            (fixture.OldToken, fixture.OldDid), (fixture.NewToken, fixture.NewDid)
        })
        {
            var response = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.Verify(
                Request(fixture, credential), new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status200OK, response.Status);
            Assert.Equal("SignedButStatusUnchecked", response.Body.GetProperty("status").GetString());
            Assert.Equal(issuer, response.Body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal(fixture.HolderDid, response.Body.GetProperty("verifiedSubject")
                .GetProperty("id").GetString());
            Assert.Equal("member", response.Body.GetProperty("verifiedSubject")
                .GetProperty("role").GetString());
        }
    }

    [Fact]
    public async Task RetiredIssuerForgeryAndWrongHolderTypeOrVocabularyNeverReleaseClaims()
    {
        var fixture = Create();
        string[] parts = fixture.NewToken.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(fixture.NewToken)
            .Replace("member", "administrator", StringComparison.Ordinal));

        foreach (var request in new[]
        {
            Request(fixture, fixture.OldToken) with { TrustedIssuerDids = [fixture.NewDid] },
            Request(fixture, string.Join('.', parts)),
            Request(fixture, fixture.NewToken) with { ExpectedHolderDid = fixture.OldDid },
            Request(fixture, fixture.NewToken) with
            {
                ExpectedCredentialType = "https://issuer.example/credentials#AdministratorCredential"
            },
            Request(fixture, fixture.NewToken) with
            {
                SubjectContextUri = new Uri("https://attacker.example/contexts/membership/v1")
            }
        })
        {
            await AssertRejectedAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.Verify(
                request, new FixedClock(Now))).ConfigureAwait(true);
        }

        await AssertRejectedAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.Verify(
            Request(fixture, fixture.NewToken), new FixedClock(Now.AddMinutes(6))))
            .ConfigureAwait(true);
    }

    [Fact]
    public async Task StatusMustBeAuthenticFromTheCredentialSignerEvenIfOtherIssuerIsEnrolled()
    {
        var fixture = Create();
        string clean = JwtVcJsonRevocationSnapshot.Create(fixture.NewDid, [],
            fixture.NewSeed, Now.AddSeconds(-5), new FixedClock(Now));
        var valid = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = clean },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, valid.Status);
        Assert.Equal("SignedNotListed", valid.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.NewDid, valid.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", valid.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        string oldIssuerSnapshot = JwtVcJsonRevocationSnapshot.Create(fixture.OldDid, [],
            fixture.OldSeed, Now.AddSeconds(-5), new FixedClock(Now));
        await AssertRejectedAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = oldIssuerSnapshot },
            new FixedClock(Now))).ConfigureAwait(true);

        string revoked = JwtVcJsonRevocationSnapshot.Create(fixture.NewDid,
            [fixture.NewToken], fixture.NewSeed, Now.AddSeconds(-5), new FixedClock(Now));
        var denied = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = revoked },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("Revoked", denied.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedSubject").ValueKind);

        await AssertRejectedAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = clean },
            new FixedClock(Now.AddSeconds(61)))).ConfigureAwait(true);
    }

    [Fact]
    public async Task InvalidOrAmbiguousTrustPolicyAndMissingStatusReturnBadRequest()
    {
        var fixture = Create();
        string[][] invalidTrust =
        [
            [], [fixture.OldDid, fixture.OldDid],
            [fixture.NewDid, "did:key:invalid"],
            Enumerable.Repeat(fixture.NewDid, 17).ToArray()
        ];
        foreach (string[] trusted in invalidTrust)
        {
            var result = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.Verify(
                Request(fixture, fixture.NewToken) with { TrustedIssuerDids = trusted },
                new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
        }

        var missing = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.VerifyWithStatus(
            Request(fixture, fixture.NewToken), new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missing.Status);

        var ignored = await ExecuteAsync(JwtVcJsonTrustedIssuerVerificationEndpoint.Verify(
            Request(fixture, fixture.NewToken) with { RevocationSnapshot = "unexpected" },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, ignored.Status);
    }

    [Fact]
    public async Task BothRoutesRequireCredentialVerifyAuthorizationAndPost()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        RouteEndpoint[] endpoints = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>().ToArray();

        foreach (string path in new[]
        {
            "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers",
            "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-with-status"
        })
        {
            var route = Assert.Single(endpoints, e => e.RoutePattern.RawText == path);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static policy => policy.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata
                .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    private static VerifyJwtVcJsonTrustedIssuersRequest Request(
        Fixture fixture, string credential) => new()
    {
        Credential = credential,
        TrustedIssuerDids = [fixture.OldDid, fixture.NewDid],
        ExpectedHolderDid = fixture.HolderDid,
        ExpectedCredentialType = CredentialType,
        SubjectContextUri = Vocabulary
    };

    private static Fixture Create()
    {
        var (oldSeed, oldDid) = NewKey();
        var (newSeed, newDid) = NewKey();
        var (_, holderDid) = NewKey();
        JsonElement claims = JsonSerializer.SerializeToElement(new
        {
            id = holderDid, role = "member"
        });
        string oldToken = JwtVcJsonCredential.Create(oldDid, holderDid,
            CredentialType, Vocabulary, claims, oldSeed,
            Now.AddMinutes(-1), Now.AddMinutes(5));
        string newToken = JwtVcJsonCredential.Create(newDid, holderDid,
            CredentialType, Vocabulary, claims, newSeed,
            Now.AddMinutes(-1), Now.AddMinutes(5));
        return new Fixture(oldDid, newDid, holderDid, oldSeed, newSeed,
            oldToken, newToken);
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

    private static async Task AssertRejectedAsync(IResult response)
    {
        var output = await ExecuteAsync(response).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, output.Status);
        Assert.Equal("Invalid", output.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, output.Body.GetProperty("verifiedSubject").ValueKind);
        Assert.Equal(JsonValueKind.Null, output.Body.GetProperty("verifiedIssuerDid").ValueKind);
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

    private sealed record Fixture(string OldDid, string NewDid, string HolderDid,
        byte[] OldSeed, byte[] NewSeed, string OldToken, string NewToken);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
