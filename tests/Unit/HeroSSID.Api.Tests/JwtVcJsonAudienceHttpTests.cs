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
            submitted, JsonSerializerOptions.Web);
        Assert.NotNull(request);

        var result = await ExecuteAsync(JwtVcJsonCredentialVerificationEndpoint.Verify(
            request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
    }


    [Fact]
    public async Task AudienceAuthenticatedSignatureAndRecipientAreRequiredBeforeClaimDisclosure()
    {
        var (seed, issuerDid) = NewIdentity();
        var (_, holderDid) = NewIdentity();
        var (_, foreignDid) = NewIdentity();
        var subject = JsonSerializer.SerializeToElement(new { id = holderDid, membership = "active" });
        string credential = JwtVcJsonCredential.CreateForAudience(issuerDid, holderDid,
            CredentialType, Vocabulary, subject, seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            Audience);
        var request = NewRequest(credential, issuerDid, holderDid, Audience);

        var accepted = await ExecuteAsync(JwtVcJsonCredentialVerificationEndpoint.VerifyForAudience(
            request, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, accepted.Status);
        Assert.Equal("SignedButStatusUnchecked", accepted.Body.GetProperty("status").GetString());
        Assert.Equal("active", accepted.Body.GetProperty("verifiedSubject")
            .GetProperty("membership").GetString());
        Assert.Equal(Now.AddMinutes(-1), accepted.Body.GetProperty("verifiedNotBefore")
            .GetDateTimeOffset());
        Assert.Equal(Now.AddMinutes(5), accepted.Body.GetProperty("verifiedExpiresAt")
            .GetDateTimeOffset());

        string unbound = JwtVcJsonCredential.Create(issuerDid, holderDid,
            CredentialType, Vocabulary, subject, seed, Now.AddMinutes(-1), Now.AddMinutes(5));
        string[] parts = credential.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(credential)
            .Replace("active", "administrator", StringComparison.Ordinal));
        foreach (var denied in new[]
        {
            NewRequest(credential, issuerDid, holderDid, new Uri("https://stranger.example/rp")),
            NewRequest(credential, foreignDid, holderDid, Audience),
            NewRequest(credential, issuerDid, foreignDid, Audience),
            NewRequest(unbound, issuerDid, holderDid, Audience),
            NewRequest(string.Join('.', parts), issuerDid, holderDid, Audience)
        })
        {
            var result = await ExecuteAsync(
                JwtVcJsonCredentialVerificationEndpoint.VerifyForAudience(
                    denied, new FixedClock(Now))).ConfigureAwait(true);
            Assert.Equal("Invalid", result.Body.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, result.Body.GetProperty("verifiedSubject").ValueKind);
            Assert.Equal(JsonValueKind.Null, result.Body.GetProperty("verifiedExpiresAt").ValueKind);
        }

        // The pre-existing no-audience route cannot accept a recipient-scoped JWT.
        var old = await ExecuteAsync(JwtVcJsonCredentialVerificationEndpoint.Verify(
            new VerifyJwtVcJsonCredentialRequest
            {
                Credential = credential, TrustedIssuerDid = issuerDid,
                ExpectedHolderDid = holderDid, ExpectedCredentialType = CredentialType,
                SubjectContextUri = Vocabulary
            }, new FixedClock(Now))).ConfigureAwait(true);
        Assert.Equal("Invalid", old.Body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task RecipientStatusIsPinnedToActualIssuerAndDoesNotReleaseRevokedClaims()
    {
        var (seed, issuerDid) = NewIdentity();
        var (_, holderDid) = NewIdentity();
        var (foreignSeed, foreignDid) = NewIdentity();
        var subject = JsonSerializer.SerializeToElement(new { id = holderDid, membership = "active" });
        string credential = JwtVcJsonCredential.CreateForAudience(issuerDid, holderDid,
            CredentialType, Vocabulary, subject, seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            Audience);
        var clock = new FixedClock(Now);
        string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [], seed, Now, clock);
        string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [credential],
            seed, Now, clock);
        string foreign = JwtVcJsonRevocationSnapshot.Create(foreignDid, [],
            foreignSeed, Now, clock);

        var accepted = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyForAudienceWithStatus(
                NewRequest(credential, issuerDid, holderDid, Audience, clean),
                clock)).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.Body.GetProperty("status").GetString());
        Assert.Equal("active", accepted.Body.GetProperty("verifiedSubject")
            .GetProperty("membership").GetString());

        foreach (var (snapshot, expected) in new[] { (revoked, "Revoked"), (foreign, "Invalid") })
        {
            var denied = await ExecuteAsync(
                JwtVcJsonCredentialVerificationEndpoint.VerifyForAudienceWithStatus(
                    NewRequest(credential, issuerDid, holderDid, Audience, snapshot),
                    clock)).ConfigureAwait(true);
            Assert.Equal(expected, denied.Body.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedSubject").ValueKind);
            Assert.Equal(JsonValueKind.Null, denied.Body.GetProperty("verifiedNotBefore").ValueKind);
        }

        var stale = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyForAudienceWithStatus(
                NewRequest(credential, issuerDid, holderDid, Audience, clean,
                    Now.AddTicks(1)), clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, stale.Status);

        var ignored = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyForAudience(
                NewRequest(credential, issuerDid, holderDid, Audience, clean),
                clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, ignored.Status);

        var missing = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyForAudience(
                NewRequest(credential, issuerDid, holderDid, null),
                clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missing.Status);

        var missingStatus = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyForAudienceWithStatus(
                NewRequest(credential, issuerDid, holderDid, Audience), clock))
            .ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, missingStatus.Status);

        var legacy = await ExecuteAsync(
            JwtVcJsonCredentialVerificationEndpoint.VerifyWithStatus(
                new VerifyJwtVcJsonCredentialWithStatusRequest
                {
                    Credential = credential, TrustedIssuerDid = issuerDid,
                    ExpectedHolderDid = holderDid, ExpectedCredentialType = CredentialType,
                    SubjectContextUri = Vocabulary, ExpectedAudience = Audience,
                    RevocationSnapshot = clean
                }, clock)).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status400BadRequest, legacy.Status);
    }

    private static VerifyJwtVcJsonForAudienceRequest NewRequest(
        string credential, string issuerDid, string holderDid, Uri? audience,
        string? snapshot = null, DateTimeOffset? cutoff = null) => new()
    {
        Credential = credential, TrustedIssuerDid = issuerDid,
        ExpectedHolderDid = holderDid, ExpectedCredentialType = CredentialType,
        SubjectContextUri = Vocabulary, ExpectedAudience = audience,
        RevocationSnapshot = snapshot, MinimumStatusObservedAt = cutoff
    };

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
