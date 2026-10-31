using System.Security.Cryptography;
using System.Text;
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

public sealed class JwtVcJsonRetiredIssuerHttpRouteTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 10, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";

    [Fact]
    public async Task RetiredExactPinRoutesArePostOnlyAndRequireCredentialVerify()
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
            "/api/v1/credentials/jwt-vc-json/verify-active-and-retired",
            "/api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-status"
        })
        {
            var route = Assert.Single(routes, route => route.RoutePattern.RawText == path);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static data => data.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata
                .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    [Fact]
    public async Task ExactRetiredPinAndCurrentIssuerSucceedButGenuineBackdatedNewOldJwtFails()
    {
        var fixture = Create();
        string oldDigest = Digest(fixture.OldToken);
        var request = Request(fixture, fixture.OldToken) with
        {
            RetiredCredentialPins =
            [
                new JwtVcJsonRetiredCredentialPin(fixture.OldDid, oldDigest)
            ]
        };

        foreach (var (token, expectedIssuer) in new[]
        {
            (fixture.OldToken, fixture.OldDid),
            (fixture.NewToken, fixture.NewDid)
        })
        {
            var verified = await ExecuteAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
                request with { Credential = token }, new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status200OK, verified.Status);
            Assert.Equal("SignedButStatusUnchecked",
                verified.Body.GetProperty("status").GetString());
            Assert.Equal(expectedIssuer,
                verified.Body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member",
                verified.Body.GetProperty("verifiedSubject").GetProperty("role").GetString());
        }

        // This JWT is GENUINELY SIGNED by the retired issuer with old iat,
        // but was never enrolled: the old key cannot mint new accepted VCs.
        string backdated = JwtVcJsonCredential.Create(fixture.OldDid,
            fixture.HolderDid, CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new
            {
                id = fixture.HolderDid, role = "administrator"
            }), fixture.OldSeed, Now.AddMinutes(-1), Now.AddMinutes(5));
        string[] parts = fixture.OldToken.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(fixture.OldToken)
                .Replace("member", "administrator", StringComparison.Ordinal));

        foreach (var rejected in new[]
        {
            request with { Credential = backdated },
            request with { Credential = string.Join('.', parts) },
            request with { RetiredCredentialPins = [] },
            request with { ExpectedHolderDid = fixture.NewDid },
            request with
            {
                ExpectedCredentialType =
                    "https://issuer.example/credentials#AdministratorCredential"
            },
            request with
            {
                SubjectContextUri = new Uri("https://attacker.example/contexts/membership/v1")
            }
        })
        {
            await AssertInvalidAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
                rejected, new FixedClock(Now))).ConfigureAwait(true);
        }

        await AssertInvalidAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
            request, new FixedClock(Now.AddMinutes(6)))).ConfigureAwait(true);
    }

    [Fact]
    public async Task RetiredStatusRequiresOriginalIssuerAndNeverLeaksRevokedClaims()
    {
        var fixture = Create();
        var request = Request(fixture, fixture.OldToken);
        string clean = JwtVcJsonRevocationSnapshot.Create(
            fixture.OldDid, [], fixture.OldSeed, Now.AddSeconds(-5),
            new FixedClock(Now));
        string foreign = JwtVcJsonRevocationSnapshot.Create(
            fixture.NewDid, [], fixture.NewSeed, Now.AddSeconds(-5),
            new FixedClock(Now));
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            fixture.OldDid, [fixture.OldToken], fixture.OldSeed,
            Now.AddSeconds(-5), new FixedClock(Now));

        var valid = await ExecuteAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithStatus(
            request with { RevocationSnapshot = clean },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", valid.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.OldDid, valid.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", valid.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        await AssertInvalidAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithStatus(
            request with { RevocationSnapshot = foreign },
            new FixedClock(Now))).ConfigureAwait(true);
        await AssertInvalidAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithStatus(
            request with { RevocationSnapshot = clean },
            new FixedClock(Now.AddSeconds(61)))).ConfigureAwait(true);

        var denial = await ExecuteAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithStatus(
            request with { RevocationSnapshot = revoked },
            new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("Revoked", denial.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denial.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, denial.Body.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task MalformedAndOverlappingPoliciesOrStatusDowngradesGetBadRequest()
    {
        var fixture = Create();
        var request = Request(fixture, fixture.OldToken);
        var pin = new JwtVcJsonRetiredCredentialPin(
            fixture.OldDid, Digest(fixture.OldToken));
        var invalid = new[]
        {
            request with { ActiveIssuerDids = [fixture.OldDid] },
            request with { ActiveIssuerDids = [fixture.NewDid, fixture.NewDid] },
            request with { ActiveIssuerDids = ["did:key:bad"] },
            request with { RetiredCredentialPins = [pin, pin] },
            request with
            {
                RetiredCredentialPins =
                [
                    new JwtVcJsonRetiredCredentialPin(fixture.OldDid,
                        pin.CredentialSha256.ToUpperInvariant())
                ]
            },
            request with { ActiveIssuerDids = [], RetiredCredentialPins = [] },
            request with { RevocationSnapshot = "caller-expects-status" },
            request with { RetiredCredentialPins = Enumerable.Repeat(pin, 257).ToArray() }
        };

        foreach (var attempt in invalid)
        {
            var response = await ExecuteAsync(JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
                attempt, new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        }

        var missing = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithStatus(
                request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missing.Status);
    }

    private static VerifyJwtVcJsonActiveAndRetiredRequest Request(
        Fixture fixture, string credential) => new()
    {
        Credential = credential,
        ActiveIssuerDids = [fixture.NewDid],
        RetiredCredentialPins =
        [
            new JwtVcJsonRetiredCredentialPin(fixture.OldDid,
                Digest(fixture.OldToken))
        ],
        ExpectedHolderDid = fixture.HolderDid,
        ExpectedCredentialType = CredentialType,
        SubjectContextUri = Vocabulary
    };

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
        using var payload = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, payload.RootElement.Clone());
    }

    private static Fixture Create()
    {
        var (oldSeed, oldDid) = NewIdentity();
        var (newSeed, newDid) = NewIdentity();
        var (_, holderDid) = NewIdentity();
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

    private static string Digest(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

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

    private sealed record Fixture(string OldDid, string NewDid, string HolderDid,
        byte[] OldSeed, byte[] NewSeed, string OldToken, string NewToken);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
