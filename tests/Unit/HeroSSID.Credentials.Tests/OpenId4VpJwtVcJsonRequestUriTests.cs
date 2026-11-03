using System.Net;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpJwtVcJsonRequestUriTests
{
    private const string Type = "https://issuer.example/credentials#Membership";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Callback = new("https://verifier.example/receive");
    private static readonly Uri RequestUri = new("https://verifier.example/oid4vp/requests/opaque");
    private readonly Clock _clock = new(new DateTimeOffset(2026, 11, 3, 4, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = Identity();
    private readonly (byte[] Seed, string Did) _holder = Identity();
    private readonly (byte[] Seed, string Did) _verifier = Identity();
    private readonly (byte[] Seed, string Did) _attacker = Identity();

    [Fact]
    public async Task ByReferenceGetVerifiesRequestAndCompletesHolderBoundPresentation()
    {
        var tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + _verifier.Did;
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, audience, _issuer.Did);
        string signedRequest = SignedRequest(challenge);
        string invocation = ByReferenceLaunch(signedRequest);
        Assert.DoesNotContain(signedRequest, invocation, StringComparison.Ordinal);
        Assert.Contains("request_uri=", invocation, StringComparison.Ordinal);

        using var handler = new ProbeHandler(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(RequestUri, request.RequestUri);
            Assert.Contains(request.Headers.Accept, x =>
                x.MediaType == "application/oauth-authz-req+jwt");
            return JwtResponse(signedRequest);
        });
        using var http = new HttpClient(handler);
        string? fetched = await Resolve(invocation, RequestUri, http);
        Assert.Equal(signedRequest, fetched);
        Assert.Equal(1, handler.Calls);

        using var subject = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(new { id = _holder.Did, membership = "active" }));
        string credential = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, Type,
            Context, subject.RootElement, _issuer.Seed, _clock.GetUtcNow().AddSeconds(-5),
            _clock.GetUtcNow().AddMinutes(5));
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            fetched!, _verifier.Did, Callback, Type, Context, credential,
            _holder.Did, _holder.Seed, _clock);
        string pin = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(signedRequest)));
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                form, fetched!, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                form, fetched!, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out _));
    }

    [Fact]
    public async Task NoFetchFromUntrustedOrAlteredLaunchAndForgedPayloadNeverPasses()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .Issue(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using var handler = new ProbeHandler(_ => JwtResponse(signed));
        using var http = new HttpClient(handler);

        Assert.Null(await Resolve(launch, new Uri("https://evil.example/oid4vp/requests/opaque"), http));
        Assert.Null(await Resolve(launch + "&request_uri=duplicate", RequestUri, http));
        Assert.Null(await Resolve(launch.Replace("https", "http", StringComparison.Ordinal),
            RequestUri, http));
        Assert.Null(await Resolve(launch.Replace("request_uri=", "request=", StringComparison.Ordinal),
            RequestUri, http));
        Assert.Equal(0, handler.Calls);

        string forged = HeroSSID.Credentials.Utilities.Ed25519JwtSigner.CreateSignedJwt(
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractHeader(signed),
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractPayload(signed),
            _attacker.Seed);
        using var forgeryHandler = new ProbeHandler(_ => JwtResponse(forged));
        using var forgeryHttp = new HttpClient(forgeryHandler);
        Assert.Null(await Resolve(launch, RequestUri, forgeryHttp));
        Assert.Equal(1, forgeryHandler.Calls);
    }

    [Fact]
    public async Task RejectsWrongContentTypeRedirectOversizedBodyAndExpiredRequest()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .Issue(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(signed, Encoding.UTF8, "text/html") }))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Redirect)
            { Headers = { Location = new Uri("https://evil.example/request") } }))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        using (var handler = new ProbeHandler(_ => JwtResponse(new string('x', 20_000))))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        _clock.Advance(TimeSpan.FromMinutes(6));
        using (var handler = new ProbeHandler(_ => JwtResponse(signed)))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }
    }

    private string SignedRequest(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, Callback, Type, Context, _clock);

    private string ByReferenceLaunch(string requestJwt) =>
        OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(requestJwt, RequestUri, _verifier.Did,
            Callback, Type, Context, _clock);

    private Task<string?> Resolve(string launch, Uri independentlyTrustedUri, HttpClient http) =>
        OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestAsync(launch, independentlyTrustedUri, http,
            _verifier.Did, Callback, Type, Context, _clock);

    private static HttpResponseMessage JwtResponse(string request) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(request, Encoding.UTF8, "application/oauth-authz-req+jwt")
        };

    private static (byte[] Seed, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed class Clock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }

    private sealed class ProbeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            HttpResponseMessage response = respond(request);
            // Real HTTP handlers attach the executed request to the response;
            // model that metadata explicitly in this isolated in-process fake.
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

}
