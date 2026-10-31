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
