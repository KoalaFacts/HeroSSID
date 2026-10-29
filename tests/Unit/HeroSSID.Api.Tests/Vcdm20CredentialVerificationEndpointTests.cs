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

public sealed class Vcdm20CredentialVerificationEndpointTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");

    [Fact]
    public async Task IndependentlyPinnedIssuerSignedVc2CanBeVerifiedOverHttpBoundary()
    {
        var fixture = CreateCredential();
        var (status, response) = await InvokeAsync(fixture.Request).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal("SignedButStatusUnchecked", response.GetProperty("status").GetString());
        Assert.Equal("member", response.GetProperty("verifiedSubject").GetProperty("role").GetString());
        Assert.Equal(fixture.HolderDid, response.GetProperty("verifiedSubject").GetProperty("id").GetString());
    }

    [Fact]
    public async Task ForgedClaimsNeverEscapeOnSignatureFailure()
    {
        var fixture = CreateCredential();
        var parts = fixture.Request.Credential!.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(fixture.Request.Credential)
                .Replace("member", "administrator", StringComparison.Ordinal));
        var request = Copy(fixture.Request, credential: string.Join('.', parts));
        var (status, response) = await InvokeAsync(request).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal("Invalid", response.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, response.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task WrongIssuerHolderTypeAndClaimVocabularyAllFailClosed()
    {
        var fixture = CreateCredential();
        var attempts = new[]
        {
            Copy(fixture.Request, issuer: fixture.HolderDid),
            Copy(fixture.Request, holder: fixture.IssuerDid),
            Copy(fixture.Request, type: "AdministratorCredential"),
            Copy(fixture.Request, context: new Uri("https://attacker.example/contexts/membership/v1"))
        };
        foreach (var request in attempts)
        {
            var (status, response) = await InvokeAsync(request).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status200OK, status);
            Assert.Equal("Invalid", response.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, response.GetProperty("verifiedSubject").ValueKind);
        }
    }

    [Fact]
    public async Task ExpiredVc2AndUnsupportedLegacyJwtNeverRevealClaims()
    {
        var fixture = CreateCredential();
        var oldClock = new FixedClock(Now.AddHours(1));
        var (expiredStatus, expired) = await InvokeAsync(fixture.Request, oldClock).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, expiredStatus);
        Assert.Equal("Invalid", expired.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, expired.GetProperty("verifiedSubject").ValueKind);

        var legacyRequest = Copy(fixture.Request, credential: "header.payload.signature");
        var (legacyStatus, legacy) = await InvokeAsync(legacyRequest).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, legacyStatus);
        Assert.Equal("Invalid", legacy.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, legacy.GetProperty("verifiedSubject").ValueKind);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task MissingCredentialReturnsBadRequest(string? token)
    {
        var fixture = CreateCredential();
        var request = new VerifyVcdm20CredentialRequest
        {
            Credential = token,
            TrustedIssuerDid = fixture.Request.TrustedIssuerDid,
            ExpectedHolderDid = fixture.Request.ExpectedHolderDid,
            ExpectedCredentialType = fixture.Request.ExpectedCredentialType,
            SubjectContextUri = fixture.Request.SubjectContextUri
        };
        var (status, _) = await InvokeAsync(request).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, status);
    }

    [Fact]
    public async Task RouteIsBoundToCredentialVerifyScopeAndPost()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        var endpoints = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(static source => source.Endpoints).OfType<RouteEndpoint>().ToArray();
        var route = Assert.Single(endpoints, static e =>
            e.RoutePattern.RawText == "/api/v1/credentials/vcdm20/verify");
        Assert.Contains(route.Metadata.GetOrderedMetadata<IAuthorizeData>(), static policy =>
            policy.Policy == "credential:verify");
        Assert.Null(route.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal("POST", Assert.Single(route.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
    }

    private static async Task<(int Status, JsonElement Response)> InvokeAsync(
        VerifyVcdm20CredentialRequest request, TimeProvider? clock = null)
    {
        var response = Vcdm20CredentialVerificationEndpoint.Verify(
            request, clock ?? new FixedClock(Now));
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var stream = new MemoryStream();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Response.Body = stream;
        await response.ExecuteAsync(http).ConfigureAwait(true);
        stream.Position = 0;
        using var payload = await JsonDocument.ParseAsync(stream).ConfigureAwait(true);
        return (http.Response.StatusCode, payload.RootElement.Clone());
    }

    private static VerifyVcdm20CredentialRequest Copy(
        VerifyVcdm20CredentialRequest original, string? credential = null,
        string? issuer = null, string? holder = null, string? type = null,
        Uri? context = null) => new()
    {
        Credential = credential ?? original.Credential,
        TrustedIssuerDid = issuer ?? original.TrustedIssuerDid,
        ExpectedHolderDid = holder ?? original.ExpectedHolderDid,
        ExpectedCredentialType = type ?? original.ExpectedCredentialType,
        SubjectContextUri = context ?? original.SubjectContextUri
    };

    private static (VerifyVcdm20CredentialRequest Request, string IssuerDid, string HolderDid)
        CreateCredential()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holder = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string issuerDid = DidFromKey(issuer.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        string token = Vcdm20JoseCredential.Create(issuerDid, holderDid, "MembershipCredential",
            Vocabulary, subject.RootElement, issuer.Export(KeyBlobFormat.RawPrivateKey),
            Now.AddMinutes(-1), Now.AddMinutes(10));
        return (new VerifyVcdm20CredentialRequest
        {
            Credential = token,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = "MembershipCredential",
            SubjectContextUri = Vocabulary
        }, issuerDid, holderDid);
    }

    private static string DidFromKey(byte[] publicKey)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        publicKey.CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
