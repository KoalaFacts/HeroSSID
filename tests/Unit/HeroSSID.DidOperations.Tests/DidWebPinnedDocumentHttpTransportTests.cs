using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
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


    [Fact]
    public async Task IsolatedTransportRejectsLoopbackBeforeOpeningTcpConnection()
    {
        // The default isolated transport must independently enforce public egress
        // even if a pinned hostname has been rebound to an internal address.
        // No TLS server is needed: the attacker must never receive a TCP SYN.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var handler =
            DidWebPinnedDocumentHttpTransport.CreateIsolatedTransportHandler();
        Assert.NotNull(handler.ConnectCallback);
        using var http = new HttpClient(handler);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            http.GetAsync(new Uri($"https://127.0.0.1:{port}/did.json"), timeout.Token));
        Assert.False(listener.Pending());
    }


    [Theory]
    [InlineData("0.0.0.0", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("100.100.100.100", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("172.20.1.1", false)]
    // IANA reserves all of 192.0.0.0/24 for protocol assignments;
    // individual public anycast exceptions must still be denied by this
    // conservative did:web HTTPS egress filter, not silently allowed.
    [InlineData("192.0.0.9", false)]
    [InlineData("192.0.0.10", false)]
    [InlineData("192.0.0.42", false)]
    [InlineData("192.0.0.170", false)]
    [InlineData("192.0.0.171", false)]
    [InlineData("192.0.0.254", false)]
    [InlineData("192.0.0.1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("192.88.99.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("198.51.100.1", false)]
    [InlineData("203.0.113.1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("::", false)]
    [InlineData("::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("3fff::1", false)]
    [InlineData("3fff:0fff::1", false)]
    // 2001::/23 is reserved for IETF assignments and is not globally
    // reachable by default; isolated HTTPS document GET fails closed for
    // the entire range, including special-purpose public exceptions.
    [InlineData("2001:0:ffff::1", false)]
    [InlineData("2001:100::1", false)]
    [InlineData("2001:1ff:ffff::1", false)]
    [InlineData("2001:200::1", true)]
    [InlineData("2001::1", false)]
    [InlineData("2002:c0a8:0101::1", false)]
    [InlineData("2001:20::1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void PublicEgressFilterRejectsNonGlobalRoutes(
        string address, bool expected)
    {
        Assert.Equal(expected,
            DidWebPinnedDocumentHttpTransport.IsPublicEgressAddress(
                IPAddress.Parse(address)));
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
            HttpResponseMessage response = send(request);
            // A raw HttpMessageHandler test double must record the originating
            // request just as the real HTTP transport does. Preserve an
            // explicitly different URI for the redirect regression test.
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }
}
