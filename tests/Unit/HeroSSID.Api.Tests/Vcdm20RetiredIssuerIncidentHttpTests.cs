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

public sealed class Vcdm20RetiredIssuerIncidentHttpTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Context =
        new("https://issuer.example/context/membership/v2");
    private readonly (byte[] Seed, string Did) _retired = NewIdentity();
    private readonly (byte[] Seed, string Did) _active = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly FixedClock _clock = new(Now);

    [Fact]
    public async Task ExactPinnedRetiredIssuerWithPostIncidentStatusReleasesAuthenticatedClaims()
    {
        string original = Issue();
        var request = Request(original, Snapshot([]));
        var response = await ExecuteAsync(
            Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                request, _clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Equal("SignedNotListed", response.Body.GetProperty("status").GetString());
        Assert.Equal(_retired.Did,
            response.Body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("member", response.Body.GetProperty("verifiedSubject")
            .GetProperty("role").GetString());
    }

    [Fact]
    public async Task SignedStaleStatusAndRevokedCredentialNeverReleaseClaims()
    {
        string original = Issue();
        string stale = Vcdm20RevocationSnapshot.Create(_retired.Did, [],
            _retired.Seed, Now.AddSeconds(-25), _clock);
        var staleResult = await ExecuteAsync(
            Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                Request(original, stale), _clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, staleResult.Status);
        Assert.Equal("Invalid", staleResult.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            staleResult.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null,
            staleResult.Body.GetProperty("verifiedSubject").ValueKind);

        var revokedResult = await ExecuteAsync(
            Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                Request(original, Snapshot([original])), _clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, revokedResult.Status);
        Assert.Equal("IssuerReportedRevoked",
            revokedResult.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            revokedResult.Body.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null,
            revokedResult.Body.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task MissingOrMalformedVerifierPolicyAndFutureCutoffAreBadRequests()
    {
        string original = Issue();
        var valid = Request(original, Snapshot([]));
        VerifyVcdm20RetiredIssuerIncidentRequest[] malformed =
        [
            valid with { MinimumObservedAt = null },
            valid with { MinimumObservedAt = Now.AddSeconds(1) },
            valid with { ActiveIssuerDids = [_active.Did, _active.Did] },
            valid with { RetiredCredentialPins =
                [new Vcdm20RetiredCredentialPin(_retired.Did, new string('A', 64))] },
            valid with { RetiredCredentialPins = [] , ActiveIssuerDids = [] },
            valid with { RevocationSnapshot = null }
        ];
        foreach (var candidate in malformed)
        {
            var rejected = await ExecuteAsync(
                Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                    candidate, _clock)).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status400BadRequest, rejected.Status);
        }
    }

    [Fact]
    public async Task ForgedOriginalOrWrongIssuerStatusDoesNotReleaseClaims()
    {
        string original = Issue();
        string good = Snapshot([]);
        var fragments = original.Split('.');
        fragments[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(original)
                .Replace("member", "administrator", StringComparison.Ordinal));
        var changed = await ExecuteAsync(
            Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                Request(string.Join('.', fragments), good), _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", changed.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            changed.Body.GetProperty("verifiedSubject").ValueKind);

        string foreign = Vcdm20RevocationSnapshot.Create(_active.Did, [],
            _active.Seed, Now.AddSeconds(-2), _clock);
        var wrongSigner = await ExecuteAsync(
            Vcdm20RetiredIssuerIncidentHttpEndpoint.VerifyWithStatusAfterCutoff(
                Request(original, foreign), _clock)).ConfigureAwait(true);
        Assert.Equal("Invalid", wrongSigner.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            wrongSigner.Body.GetProperty("verifiedIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RouteIsAuthenticatedAndRequiresCredentialVerifyScope()
    {
        var builder = WebApplication.CreateBuilder(
            new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        var routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>();
        var route = Assert.Single(routes, x => x.RoutePattern.RawText ==
            "/api/v1/credentials/vcdm20/verify-active-and-retired-after-incident");
        Assert.Equal("POST",
            Assert.Single(route.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            x => x.Policy == "credential:verify");
        Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
    }

    private VerifyVcdm20RetiredIssuerIncidentRequest Request(
        string original, string snapshot) => new()
    {
        Credential = original,
        ActiveIssuerDids = [_active.Did],
        RetiredCredentialPins =
        [
            new Vcdm20RetiredCredentialPin(_retired.Did,
                Convert.ToHexStringLower(SHA256.HashData(
                    Encoding.UTF8.GetBytes(IssueCanonical(original)))))
        ],
        ExpectedHolderDid = _holder.Did,
        ExpectedCredentialType = "MembershipCredential",
        SubjectContextUri = Context,
        RevocationSnapshot = snapshot,
        MinimumObservedAt = Now.AddSeconds(-10)
    };

    private static string IssueCanonical(string original) => original;

    private string Issue()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, role = "member" }));
        return Vcdm20JoseCredential.Create(
            _retired.Did, _holder.Did, "MembershipCredential", Context,
            subject.RootElement, _retired.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(_retired.Did, revoked,
            _retired.Seed, Now.AddSeconds(-2), _clock);

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult response)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = stream;
        await response.ExecuteAsync(context).ConfigureAwait(true);
        stream.Position = 0;
        using var document = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (context.Response.StatusCode, document.RootElement.Clone());
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var rawKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefix = new byte[34];
        prefix[0] = 0xed;
        prefix[1] = 0x01;
        rawKey.CopyTo(prefix, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefix));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
