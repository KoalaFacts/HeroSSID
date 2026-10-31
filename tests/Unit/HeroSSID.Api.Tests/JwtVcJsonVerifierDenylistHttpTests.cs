using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Credentials.JwtVcJson;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class JwtVcJsonVerifierDenylistHttpTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 1, 3, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary =
        new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType =
        "https://issuer.example/credentials#MembershipCredential";

    [Fact]
    public async Task ExplicitDenylistRoutesMustRequireCredentialVerify()
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
            "/api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-denylist",
            "/api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-denylist-and-status"
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
    public async Task LegacyRouteMustRejectRatherThanSilentlyDiscardSubmittedEmergencyPolicy()
    {
        var (issuerSeed, issuerDid) = NewIdentity();
        var (_, holderDid) = NewIdentity();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid,
            CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(5));
        string digest = Digest(credential);

        // Construct an actual HTTP JSON payload with the NEW security field.
        // The old DTO silently ignores this unknown property on baseline main.
        string body = JsonSerializer.Serialize(new
        {
            Credential = credential,
            ActiveIssuerDids = new[] { issuerDid },
            RetiredCredentialPins = Array.Empty<JwtVcJsonRetiredCredentialPin>(),
            DeniedCredentialSha256 = new[] { digest },
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = CredentialType,
            SubjectContextUri = Vocabulary
        });
        var request = JsonSerializer.Deserialize<VerifyJwtVcJsonActiveAndRetiredRequest>(body);
        Assert.NotNull(request);

        var result = JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
            request, new FixedClock(Now));
        var response = await ExecuteAsync(result).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
    }


    [Fact]
    public async Task GenuineActiveAndExactPinnedRetiredJwtCanBeDeniedWithoutDisclosingClaims()
    {
        var fixture = CreateFixture();
        foreach (string token in new[] { fixture.NewToken, fixture.OldToken })
        {
            var request = Request(fixture, token) with
            {
                DeniedCredentialSha256 = [Digest(token)]
            };
            await AssertBlockedAsync(
                JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                    request, new FixedClock(Now)), "DeniedByVerifier").ConfigureAwait(true);
        }

        // The same authentic old token passes when no independent denial is
        // configured and it is pinned to the original retired issuer signature.
        var allowed = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                Request(fixture, fixture.OldToken), new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, allowed.Status);
        Assert.Equal("SignedButStatusUnchecked",
            allowed.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.OldDid,
            allowed.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", allowed.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());
    }

    [Fact]
    public async Task AuthenticCleanIssuerStatusCannotOverrideIndependentDenial()
    {
        var fixture = CreateFixture();
        string clean = JwtVcJsonRevocationSnapshot.Create(
            fixture.NewDid, [], fixture.NewSeed, Now.AddSeconds(-5),
            new FixedClock(Now));
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            fixture.NewDid, [fixture.NewToken], fixture.NewSeed,
            Now.AddSeconds(-5), new FixedClock(Now));
        string foreign = JwtVcJsonRevocationSnapshot.Create(
            fixture.OldDid, [], fixture.OldSeed, Now.AddSeconds(-5),
            new FixedClock(Now));
        var request = Request(fixture, fixture.NewToken) with
        {
            DeniedCredentialSha256 = [Digest(fixture.NewToken)],
            RevocationSnapshot = clean
        };

        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request, new FixedClock(Now)), "DeniedByVerifier").ConfigureAwait(true);

        var allowed = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request with { DeniedCredentialSha256 = [] }, new FixedClock(Now)))
            .ConfigureAwait(true);
        Assert.Equal("SignedNotListed",
            allowed.Body.GetProperty("status").GetString());
        Assert.Equal(fixture.NewDid,
            allowed.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", allowed.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request with { DeniedCredentialSha256 = [], RevocationSnapshot = revoked },
                new FixedClock(Now)), "IssuerReportedRevoked").ConfigureAwait(true);
        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request with { RevocationSnapshot = foreign },
                new FixedClock(Now)), "Invalid").ConfigureAwait(true);
        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request, new FixedClock(Now.AddSeconds(61))),
            "Invalid").ConfigureAwait(true);
    }

    [Fact]
    public async Task DenylistDoesNotAuthenticateOutsidersWrongHolderOrUnpinnedOldJwt()
    {
        var fixture = CreateFixture();
        var (outsiderSeed, outsiderDid) = NewIdentity();
        string outsider = JwtVcJsonCredential.Create(
            outsiderDid, fixture.HolderDid, CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new
            {
                id = fixture.HolderDid, role = "administrator"
            }), outsiderSeed, Now.AddMinutes(-1), Now.AddMinutes(5));

        var request = Request(fixture, outsider) with
        {
            DeniedCredentialSha256 = [Digest(outsider)]
        };
        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                request, new FixedClock(Now)), "Invalid").ConfigureAwait(true);
        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                Request(fixture, fixture.NewToken) with
                {
                    DeniedCredentialSha256 = [Digest(fixture.NewToken)],
                    ExpectedHolderDid = fixture.OldDid
                }, new FixedClock(Now)), "Invalid").ConfigureAwait(true);
        await AssertBlockedAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                Request(fixture, fixture.OldToken) with
                {
                    DeniedCredentialSha256 = [Digest(fixture.OldToken)],
                    RetiredCredentialPins = []
                }, new FixedClock(Now)), "Invalid").ConfigureAwait(true);
    }

    [Fact]
    public async Task DenylistPolicyIsBoundedCanonicalUniqueAndNeverSilentlyDowngraded()
    {
        var fixture = CreateFixture();
        var request = Request(fixture, fixture.NewToken);
        string digest = Digest(fixture.NewToken);
        var malformed = new[]
        {
            request with { DeniedCredentialSha256 = null },
            request with { DeniedCredentialSha256 = [digest, digest] },
            request with { DeniedCredentialSha256 = [digest.ToUpperInvariant()] },
            request with { DeniedCredentialSha256 = ["not-a-digest"] },
            request with { DeniedCredentialSha256 = Enumerable.Repeat(digest, 257).ToArray() },
            request with { RevocationSnapshot = "status-must-not-be-ignored" }
        };
        foreach (var attempt in malformed)
        {
            var response = await ExecuteAsync(
                JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                    attempt, new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        }

        var missingStatus = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylistAndStatus(
                request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missingStatus.Status);
        var legacy = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.Verify(
                request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, legacy.Status);
    }

    private static VerifyJwtVcJsonActiveAndRetiredRequest Request(
        Fixture fixture, string token) => new()
    {
        Credential = token,
        ActiveIssuerDids = [fixture.NewDid],
        RetiredCredentialPins =
        [
            new JwtVcJsonRetiredCredentialPin(
                fixture.OldDid, Digest(fixture.OldToken))
        ],
        DeniedCredentialSha256 = [],
        ExpectedHolderDid = fixture.HolderDid,
        ExpectedCredentialType = CredentialType,
        SubjectContextUri = Vocabulary
    };

    private static Fixture CreateFixture()
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
        return new Fixture(oldSeed, oldDid, newSeed, newDid, holderDid,
            oldToken, newToken);
    }

    private static async Task AssertBlockedAsync(IResult result, string expectedStatus)
    {
        var response = await ExecuteAsync(result).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal(expectedStatus, response.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, response.Body.GetProperty("verifiedSubject").ValueKind);
    }

    private sealed record Fixture(byte[] OldSeed, string OldDid,
        byte[] NewSeed, string NewDid, string HolderDid,
        string OldToken, string NewToken);

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = stream;
        await result.ExecuteAsync(context).ConfigureAwait(true);
        stream.Position = 0;
        using var payload = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (context.Response.StatusCode, payload.RootElement.Clone());
    }

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

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

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
