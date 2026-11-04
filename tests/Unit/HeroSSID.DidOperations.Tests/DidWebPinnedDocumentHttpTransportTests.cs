using System.Net;
using System.Net.Http.Headers;
using System.Text;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedDocumentHttpTransportTests
{
    [Fact]
    public async Task FetchesOnlyCanonicalPinnedRootDocumentAndVerifiesKey()
    {
        (string did, byte[] key, string json) = Document();
        int calls = 0;
        using var handler = new FakeHandler(request =>
        {
            calls++;
            Assert.Equal("https://issuer.example.org/.well-known/did.json",
                request.RequestUri!.AbsoluteUri);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Null(request.Headers.Authorization);
            return JsonResponse(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);

        Assert.True(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, http, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task FetchesCanonicalPathWithoutAcceptingKeySubstitution()
    {
        (string did, byte[] key, string json) = Document("did:web:issuer.example.org:teams:acme");
        using Key other = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] substituted = other.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        using var handler = new FakeHandler(request =>
        {
            Assert.Equal("https://issuer.example.org/teams/acme/did.json",
                request.RequestUri!.AbsoluteUri);
            return JsonResponse(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);

        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, substituted, http, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(HttpStatusCode.Redirect)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task FailsClosedOnNonSuccessStatus(HttpStatusCode status)
    {
        (string did, byte[] key, string json) = Document();
        using var handler = new FakeHandler(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/did+ld+json")
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, http, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("text/html")]
    [InlineData("application/octet-stream")]
    public async Task RejectsUnexpectedContentType(string contentType)
    {
        (string did, byte[] key, string json) = Document();
        using var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, contentType)
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, http, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsOversizedUnannouncedBodiesAndWrongKey()
    {
        (string did, byte[] key, string json) = Document();
        using var largeHandler = new FakeHandler(_ => JsonResponse(
            new string(' ', 16_385) + json));
        using var tooLarge = new HttpClient(largeHandler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, tooLarge, cancellationToken: TestContext.Current.CancellationToken));

        using var maliciousHandler = new FakeHandler(_ => JsonResponse(
            json.Replace("issuer.example.org", "attacker.example.org",
                StringComparison.Ordinal)));
        using var malicious = new HttpClient(maliciousHandler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, malicious, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsDefaultAuthorizationBeforeNetworkAccess()
    {
        (string did, byte[] key, string json) = Document();
        int calls = 0;
        using var handler = new FakeHandler(_ =>
        {
            calls++;
            return JsonResponse(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "private-token");
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, http, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task RefusesResponseFromDifferentFinalUri()
    {
        (string did, byte[] key, string json) = Document();
        using var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(
                HttpMethod.Get, "https://attacker.example.org/did.json"),
            Content = new StringContent(json, Encoding.UTF8,
                "application/did+ld+json")
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            did, key, http, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsUntrustedInputBeforeAnyRequest()
    {
        (string _, byte[] key, string json) = Document();
        int calls = 0;
        using var handler = new FakeHandler(_ =>
        {
            calls++;
            return JsonResponse(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            "did:web:127.0.0x1", key, http, cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchAsync(
            "did:web:issuer.example.org", key[..31], http, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, calls);
    }

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8,
                "application/did+ld+json")
        };

    private static (string Did, byte[] PublicKey, string Json) Document(
        string did = "did:web:issuer.example.org")
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        return (did, publicKey,
            new DidWebMethod().CreateDidDocument(did, publicKey));
    }

    private sealed class FakeHandler(
        Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(send(request));
        }
    }
}
