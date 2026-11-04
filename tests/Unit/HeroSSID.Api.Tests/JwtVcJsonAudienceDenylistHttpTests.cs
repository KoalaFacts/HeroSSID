using System.Reflection;
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

/// <summary>
/// Real Ed25519-signed issuer tokens at the non-.NET verification boundary.
/// The HTTP caller owns the recipient, issuer, holder and denial policies.
/// An issuer signature alone never grants authority or holder control.
/// </summary>
public sealed class JwtVcJsonAudienceDenylistHttpTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 4, 8, 0, 0, TimeSpan.Zero);
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/intake");
    private static readonly Uri WrongRecipient = new("https://other.example/intake");
    private static readonly Uri AnotherAllowedRecipient = new("https://second.example/intake");
    private const string Type = "https://issuer.example/credentials#Member";

    [Fact]
    public async Task RecipientDenylistRoutesMustRequireCredentialVerify()
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
            "/api/v1/credentials/jwt-vc-json/verify-for-audience-with-denylist",
            "/api/v1/credentials/jwt-vc-json/verify-for-audience-with-denylist-and-status"
        })
        {
            var route = Assert.Single(routes, route => route.RoutePattern.RawText == path);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static policy => policy.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata
                .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    [Fact]
    public async Task ActiveAndExactlyPinnedRetiredRecipientsCanBeDeniedBeforeClaimRelease()
    {
        var old = Identity();
        var active = Identity();
        var holder = Identity();
        string oldJwt = Issue(old, holder.Did, "member");
        string activeJwt = Issue(active, holder.Did, "member");
        string unpinnedFresh = Issue(old, holder.Did, "admin");
        var pin = new JwtVcJsonRetiredCredentialPin(old.Did, Digest(oldJwt));

        foreach (var (jwt, issuer) in new[]
        {
            (oldJwt, old.Did), (activeJwt, active.Did)
        })
        {
            var request = Request(jwt, active.Did, holder.Did, pin);
            var allowed = await InvokeAsync("VerifyForAudienceWithDenylist", request)
                .ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status200OK, allowed.Status);
            Assert.Equal("SignedButStatusUnchecked", allowed.Body.GetProperty("status").GetString());
            Assert.Equal(issuer, allowed.Body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member", allowed.Body.GetProperty("verifiedSubject")
                .GetProperty("role").GetString());

            await AssertHiddenAsync("VerifyForAudienceWithDenylist",
                request with { DeniedCredentialSha256 = [Digest(jwt)] },
                "DeniedByVerifier").ConfigureAwait(true);
            await AssertHiddenAsync("VerifyForAudienceWithDenylist",
                WithAudience(request, WrongRecipient),
                "Invalid").ConfigureAwait(true);
            await AssertHiddenAsync("VerifyForAudienceWithDenylist",
                request with { ExpectedHolderDid = active.Did },
                "Invalid").ConfigureAwait(true);
        }

        await AssertHiddenAsync("VerifyForAudienceWithDenylist",
            Request(unpinnedFresh, active.Did, holder.Did, pin), "Invalid")
            .ConfigureAwait(true);

        await AssertHiddenAsync("VerifyForAudienceWithDenylist",
            Request(oldJwt, active.Did, holder.Did, pin) with
            {
                RetiredCredentialPins = []
            }, "Invalid").ConfigureAwait(true);
    }

    [Fact]
    public async Task GenuineIssuerStatusCannotOverrideDenialAndPolicyCannotBeDowngraded()
    {
        var issuer = Identity();
        var holder = Identity();
        var outsider = Identity();
        string jwt = Issue(issuer, holder.Did, "member");
        string clean = Snapshot(issuer, []);
        string revoked = Snapshot(issuer, [jwt]);
        string foreign = Snapshot(outsider, []);
        var request = Request(jwt, issuer.Did, holder.Did) with
        {
            RevocationSnapshot = clean
        };
        var allowed = await InvokeAsync("VerifyForAudienceWithDenylistAndStatus", request)
            .ConfigureAwait(true);
        Assert.Equal("SignedNotListed", allowed.Body.GetProperty("status").GetString());
        Assert.Equal("member", allowed.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        await AssertHiddenAsync("VerifyForAudienceWithDenylistAndStatus",
            request with { DeniedCredentialSha256 = [Digest(jwt)] },
            "DeniedByVerifier").ConfigureAwait(true);
        await AssertHiddenAsync("VerifyForAudienceWithDenylistAndStatus",
            request with { RevocationSnapshot = revoked },
            "IssuerReportedRevoked").ConfigureAwait(true);
        await AssertHiddenAsync("VerifyForAudienceWithDenylistAndStatus",
            request with { RevocationSnapshot = foreign },
            "Invalid").ConfigureAwait(true);

        foreach (var invalid in new[]
        {
            WithAudience(request, null),
            WithAudience(request, new Uri("http://verifier.example/intake")),
            WithAudience(request, new Uri("https://verifier.example/intake#frag")),
            request with { DeniedCredentialSha256 = null },
            request with { DeniedCredentialSha256 = [Digest(jwt), Digest(jwt)] },
            request with { DeniedCredentialSha256 = [Digest(jwt).ToUpperInvariant()] }
        })
        {
            var response = await InvokeAsync("VerifyForAudienceWithDenylistAndStatus", invalid)
                .ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        }

        var missing = await InvokeAsync("VerifyForAudienceWithDenylist", request)
            .ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missing.Status);

        // The old security routes must reject a submitted independent recipient
        // pin even for a perfectly valid NO-audience JWT; ignoring it is unsafe.
        string legacy = JwtVcJsonCredential.Create(issuer.Did, holder.Did,
            Type, Context, JsonSerializer.SerializeToElement(new
            {
                id = holder.Did, role = "member"
            }), issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5));
        string wire = JsonSerializer.Serialize(new
        {
            Credential = legacy,
            ActiveIssuerDids = new[] { issuer.Did },
            RetiredCredentialPins = Array.Empty<JwtVcJsonRetiredCredentialPin>(),
            DeniedCredentialSha256 = Array.Empty<string>(),
            ExpectedHolderDid = holder.Did,
            ExpectedCredentialType = Type,
            SubjectContextUri = Context,
            ExpectedAudience = Recipient
        });
        var deserialized = JsonSerializer.Deserialize<VerifyJwtVcJsonActiveAndRetiredRequest>(wire);
        Assert.NotNull(deserialized);
        var oldResult = await ExecuteAsync(
            JwtVcJsonRetiredIssuerVerificationEndpoint.VerifyWithDenylist(
                deserialized, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, oldResult.Status);
    }

    [Fact]
    public async Task IndependentIncidentCutoffRejectsPreIncidentStatusAndUncheckedDowngrade()
    {
        var issuer = Identity();
        var holder = Identity();
        string jwt = Issue(issuer, holder.Did, "member");
        string beforeIncident = JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, [], issuer.Seed, Now.AddSeconds(-20), new FixedClock(Now));
        var request = WithStatusCutoff(Request(jwt, issuer.Did, holder.Did) with
        {
            RevocationSnapshot = beforeIncident
        }, Now.AddSeconds(-10));

        // A genuine same-issuer snapshot within its 60-second validity
        // must NOT disclose claims if it predates the verifier's incident.
        await AssertHiddenAsync("VerifyForAudienceWithDenylistAndStatus",
            request, "Invalid").ConfigureAwait(true);

        // The snapshot's observation has only whole-second precision.
        // A cutoff one 100ns tick later must not round back and accept it.
        await AssertHiddenAsync("VerifyForAudienceWithDenylistAndStatus",
            WithStatusCutoff(request, Now.AddSeconds(-20).AddTicks(1)),
            "Invalid").ConfigureAwait(true);

        var exactBoundary = await InvokeAsync("VerifyForAudienceWithDenylistAndStatus",
            WithStatusCutoff(request, Now.AddSeconds(-20))).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", exactBoundary.Body.GetProperty("status").GetString());

        string afterIncident = Snapshot(issuer, []);
        var accepted = await InvokeAsync("VerifyForAudienceWithDenylistAndStatus",
            request with { RevocationSnapshot = afterIncident }).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.Body.GetProperty("status").GetString());
        Assert.Equal("member", accepted.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());

        // A caller must not silently lose the cutoff on a status-unchecked
        // route, including when no status JWT is submitted.
        var downgraded = await InvokeAsync("VerifyForAudienceWithDenylist",
            request with { RevocationSnapshot = null }).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, downgraded.Status);

        var future = await InvokeAsync("VerifyForAudienceWithDenylistAndStatus",
            WithStatusCutoff(request, Now.AddTicks(1))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, future.Status);
    }

    private static VerifyJwtVcJsonActiveAndRetiredRequest WithStatusCutoff(
        VerifyJwtVcJsonActiveAndRetiredRequest request, DateTimeOffset minimumObservedAt)
    {
        // Test-only JSON bridge preserves a compilable runtime RED before
        // production adds this verifier-owned policy member to the DTO.
        var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            JsonSerializer.Serialize(request))!;
        values["MinimumStatusObservedAt"] = JsonSerializer.SerializeToElement(minimumObservedAt);
        return JsonSerializer.Deserialize<VerifyJwtVcJsonActiveAndRetiredRequest>(
            JsonSerializer.Serialize(values))!;
    }

    private static VerifyJwtVcJsonActiveAndRetiredRequest Request(
        string jwt, string activeDid, string holderDid,
        JwtVcJsonRetiredCredentialPin? pin = null) => WithAudience(new()
    {
        Credential = jwt,
        ActiveIssuerDids = [activeDid],
        RetiredCredentialPins = pin is null ? [] : [pin],
        DeniedCredentialSha256 = [],
        ExpectedHolderDid = holderDid,
        ExpectedCredentialType = Type,
        SubjectContextUri = Context
    }, Recipient);

    private static VerifyJwtVcJsonActiveAndRetiredRequest WithAudience(
        VerifyJwtVcJsonActiveAndRetiredRequest request, Uri? audience)
    {
        // JSON bridges test-only RED against baseline DTO without this field.
        // Production must explicitly bind this caller-owned policy.
        var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            JsonSerializer.Serialize(request))!;
        values["ExpectedAudience"] = JsonSerializer.SerializeToElement(audience);
        return JsonSerializer.Deserialize<VerifyJwtVcJsonActiveAndRetiredRequest>(
            JsonSerializer.Serialize(values))!;
    }

    private static async Task AssertHiddenAsync(string method,
        VerifyJwtVcJsonActiveAndRetiredRequest request, string expected)
    {
        var response = await InvokeAsync(method, request).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal(expected, response.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            response.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null,
            response.Body.GetProperty("verifiedSubject").ValueKind);
    }

    private static Task<(int Status, JsonElement Body)> InvokeAsync(
        string methodName, VerifyJwtVcJsonActiveAndRetiredRequest request)
    {
        // Reflection keeps the test-only red commit compilable and produces
        // actual xUnit runtime failures until the production route exists.
        MethodInfo? method = typeof(JwtVcJsonRetiredIssuerVerificationEndpoint)
            .GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        var result = Assert.IsAssignableFrom<IResult>(
            method.Invoke(null, [request, new FixedClock(Now)]));
        return ExecuteAsync(result);
    }

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = stream;
        await result.ExecuteAsync(context).ConfigureAwait(true);
        stream.Position = 0;
        using var document = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (context.Response.StatusCode, document.RootElement.Clone());
    }

    private static string Issue((byte[] Seed, string Did) issuer,
        string holderDid, string role) =>
        JwtVcJsonCredential.CreateForAudiencesWithMetadata(
            issuer.Did, holderDid, Type, Context,
            JsonSerializer.SerializeToElement(new { id = holderDid, role }),
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            [Recipient, AnotherAllowedRecipient], null, null, exactValidity: false);

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, revoked, issuer.Seed, Now, new FixedClock(Now));

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

    private static (byte[] Seed, string Did) Identity()
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

    private sealed class FixedClock(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }
}
