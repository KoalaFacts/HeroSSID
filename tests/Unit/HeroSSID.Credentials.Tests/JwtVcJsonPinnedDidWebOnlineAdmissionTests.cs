using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real Ed25519 issuer/holder/verifier keys with an isolated HTTP contract probe.
/// An HTTP probe does not establish external Wallet interoperability.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebOnlineAdmissionTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string Method = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");
    private static readonly Uri StatusUri = new("https://issuer.example/status/member-42.jwt");

    [Fact]
    public async Task AuthenticRemoteNotRevokedStatusAdmitsRealHolderOnlyOnce()
    {
        Fixture f = CreateFixture();
        using var handler = new StatusProbeHandler(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(StatusUri, request.RequestUri);
            Assert.Null(request.Headers.Authorization);
            Assert.Single(request.Headers.Accept);
            return Response(Status(f, false));
        });
        using var http = new HttpClient(handler);
        var allowed = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            allowed.Result);
        Assert.Equal("member", allowed.VerifiedSubject.GetProperty("role").GetString());
        var replay = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, replay.Result);
        Assert.Equal(JsonValueKind.Undefined, replay.VerifiedSubject.ValueKind);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task AuthenticIssuerRevocationSpendsNonceWithoutReleasingClaims()
    {
        Fixture f = CreateFixture();
        using var handler = new StatusProbeHandler(_ => Response(Status(f, true)));
        using var http = new HttpClient(handler);
        var refused = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.RevokedByIssuer,
            refused.Result);
        Assert.Equal(JsonValueKind.Undefined, refused.VerifiedSubject.ValueKind);
        var replay = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, replay.Result);
    }

    [Fact]
    public async Task VerifierEmergencyDenialOverridesGenuineIssuerStatusAndSpendsNonce()
    {
        Fixture f = CreateFixture();
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(f.CredentialJwt)));
        using var handler = new StatusProbeHandler(_ => Response(Status(f, false)));
        using var http = new HttpClient(handler);
        var refused = await CheckAsync(f, http, [digest], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.DeniedByVerifier,
            refused.Result);
        Assert.Equal(JsonValueKind.Undefined, refused.VerifiedSubject.ValueKind);
        var replay = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, replay.Result);
    }

    [Fact]
    public async Task MissingOrForgedIssuerStatusDoesNotSpendValidHolderChallenge()
    {
        Fixture f = CreateFixture();
        var foreign = Identity();
        string authentic = Status(f, false);
        string forged = HeroSSID.Credentials.Utilities.Ed25519JwtSigner.CreateSignedJwt(
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractHeader(authentic),
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractPayload(authentic),
            foreign.Seed);
        bool fail = true;
        using var handler = new StatusProbeHandler(_ =>
            fail ? Response(forged) : Response(authentic));
        using var http = new HttpClient(handler);
        var refused = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, refused.Result);
        Assert.Equal(JsonValueKind.Undefined, refused.VerifiedSubject.ValueKind);
        fail = false;
        var allowed = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            allowed.Result);
    }

    [Fact]
    public async Task ForeignOrUnrelatedOriginalAndMalformedPolicyDoNotCauseNetworkOrSpendNonce()
    {
        Fixture f = CreateFixture();
        var foreign = Identity();
        using var handler = new StatusProbeHandler(_ => Response(Status(f, false)));
        using var http = new HttpClient(handler);
        var unrelated = await CheckAsync(f, http, [], "not.a.real.jwt");
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, unrelated.Result);
        var invalidPolicy = await CheckAsync(f, http, ["NOT-A-SHA256"], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, invalidPolicy.Result);
        Assert.Equal(0, handler.Calls);
        var invalidKey = await CheckAsync(f, http, [], f.CredentialJwt, foreign.PublicKey);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid, invalidKey.Result);
        Assert.Equal(0, handler.Calls);
        var accepted = await CheckAsync(f, http, [], f.CredentialJwt);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            accepted.Result);
        Assert.Equal("member", accepted.VerifiedSubject.GetProperty("role").GetString());
    }

    private static Task<JwtVcJsonPinnedDidWebOnlineAdmissionResponse> CheckAsync(
        Fixture f, HttpClient http, IReadOnlyCollection<string> denied,
        string original, byte[]? key = null) =>
        JwtVcJsonPinnedDidWebOnlineAdmission.CheckAsync(
            StatusUri, http, original, f.PresentationJwt, f.Tenant, f.Audience,
            f.Nonce, IssuerDid, Method, key ?? f.IssuerPublicKey, IssuerName,
            CredentialId, CredentialType, Context, denied, f.Store, f.Clock);

    private static string Status(Fixture f, bool revoked) =>
        JwtVcJsonPinnedDidWebIssuerStatus.Create(
            f.CredentialJwt, IssuerDid, Method, f.IssuerPublicKey,
            f.IssuerSeed, revoked, f.Clock.GetUtcNow(), f.Clock);

    private static HttpResponseMessage Response(string jwt)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.ASCII)
        };
        response.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/jwt");
        return response;
    }

    private sealed class StatusProbeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            var response = respond(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

    private static Fixture CreateFixture()
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        TimeProvider clock = TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + verifier.Did;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(tenant, audience, IssuerDid);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, role = "member" }));
        DateTimeOffset now = clock.GetUtcNow();
        string credential = JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, Method, issuer.PublicKey, holder.Did, CredentialType, Context,
            document.RootElement, issuer.Seed, now.AddMinutes(-1), now.AddMinutes(4),
            IssuerName, CredentialId);
        string vp = JwtVcJsonPinnedDidWebIssuerPresentation.Create(
            challenge, credential, IssuerDid, Method, issuer.PublicKey,
            IssuerName, CredentialId, CredentialType, Context,
            holder.Did, holder.Seed, clock);
        return new Fixture(credential, vp, tenant, audience, challenge.Nonce,
            issuer.Seed, issuer.PublicKey, store, clock);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }

    private sealed record Fixture(
        string CredentialJwt, string PresentationJwt, Guid Tenant, string Audience,
        string Nonce, byte[] IssuerSeed, byte[] IssuerPublicKey,
        IPresentationChallengeStore Store, TimeProvider Clock);
}
