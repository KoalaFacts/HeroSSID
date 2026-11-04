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

/// <summary>
/// HTTP audience policy is verifier-owned and cannot be silently ignored.
/// Tests exercise the real Ed25519 signer and the actual Minimal API results.
/// </summary>
public sealed class JwtVcJsonAudienceHttpTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 4, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Audience = new("https://verifier.example/credentials");
    private const string CredentialType = "https://issuer.example/credentials#Membership";

    [Fact]
    public async Task AudienceVerificationRoutesRequireExplicitCredentialVerifyPolicy()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        RouteEndpoint[] routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>().ToArray();

        foreach (string path in new[]
        {
            "/api/v1/credentials/jwt-vc-json/verify-for-audience",
            "/api/v1/credentials/jwt-vc-json/verify-for-audience-with-status"
        })
        {
            var route = Assert.Single(routes, r => r.RoutePattern.RawText == path);
            Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(),
                static p => p.Policy == "credential:verify");
            Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
            Assert.Equal("POST", Assert.Single(route.Metadata
                .GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        }
    }

    [Fact]
    public async Task LegacyVerifyMustRejectSubmittedAudiencePolicyInsteadOfIgnoringIt()
    {
        var (seed, issuerDid) = NewIdentity();
        var (_, holderDid) = NewIdentity();
        var subject = JsonSerializer.SerializeToElement(new { id = holderDid, membership = "active" });
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid,
            CredentialType, Vocabulary, subject, seed, Now.AddMinutes(-1), Now.AddMinutes(5));

        // Actual HTTP JSON sent by a caller who believes an audience is enforced.
        // On baseline main this unknown property is silently discarded.
        string submitted = JsonSerializer.Serialize(new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = CredentialType, subjectContextUri = Vocabulary,
            expectedAudience = Audience
        });
        var request = JsonSerializer.Deserialize<VerifyJwtVcJsonCredentialRequest>(
            submitted, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(request);

        var result = await ExecuteAsync(JwtVcJsonCredentialVerificationEndpoint.Verify(
            request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
    }

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await result.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var json = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, json.RootElement.Clone());
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

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
