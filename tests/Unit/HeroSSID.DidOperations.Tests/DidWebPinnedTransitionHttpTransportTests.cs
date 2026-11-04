using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedTransitionHttpTransportTests
{
    [Theory]
    [InlineData("did:web:issuer.example.org", "https://issuer.example.org/.well-known/did.json")]
    [InlineData("did:web:issuer.example.org:organisations:acme", "https://issuer.example.org/organisations/acme/did.json")]
    public async Task FetchesExactTwoKeyOverlapWithBothIndependentlyPinnedKeys(
        string did, string expectedUri)
    {
        (byte[] oldKey, byte[] newKey, string json) = Document(did);
        int calls = 0;
        using var handler = new FakeHandler(request =>
        {
            calls++;
            Assert.Equal(expectedUri, request.RequestUri!.AbsoluteUri);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Null(request.Headers.Authorization);
            return Response(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.True(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, http, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task RejectsSubstitutedSuccessorAndUnauthorizedDelegation()
    {
        const string did = "did:web:issuer.example.org";
        (byte[] oldKey, byte[] newKey, string json) = Document(did);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] wrongKey = attacker.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        using var handler = new FakeHandler(_ => Response(json));
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, wrongKey, http,
            cancellationToken: TestContext.Current.CancellationToken));

        JsonNode tampered = JsonNode.Parse(json)!;
        tampered["capabilityDelegation"] = new JsonArray(did + "#key-2");
        using var alteredHandler = new FakeHandler(_ => Response(tampered.ToJsonString()));
        using var alteredHttp = new HttpClient(alteredHandler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, alteredHttp,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsSingleKeyDocumentAndRedirectedDestination()
    {
        const string did = "did:web:issuer.example.org";
        (byte[] oldKey, byte[] newKey, _) = Document(did);
        using var handler = new FakeHandler(_ => Response(
            new DidWebMethod().CreateDidDocument(did, oldKey)));
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, http,
            cancellationToken: TestContext.Current.CancellationToken));

        using var redirectedHandler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(
                HttpMethod.Get, "https://attacker.example.org/did.json"),
            Content = new StringContent(
                DidWebPinnedKeyTransition.CreateTransitionDocument(did, oldKey, newKey),
                Encoding.UTF8, "application/did+ld+json")
        });
        using var redirectedHttp = new HttpClient(redirectedHandler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, redirectedHttp,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsUntrustedPinsAndClientCredentialsBeforeNetwork()
    {
        const string did = "did:web:issuer.example.org";
        (byte[] oldKey, byte[] newKey, string json) = Document(did);
        int calls = 0;
        using var handler = new FakeHandler(_ =>
        {
            calls++;
            return Response(json);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, oldKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey[..31], newKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            "did:web:127.0.0x1", oldKey, newKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "secret");
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task RejectsUnannouncedOversizedResponse()
    {
        const string did = "did:web:issuer.example.org";
        (byte[] oldKey, byte[] newKey, string json) = Document(did);
        using var handler = new FakeHandler(_ => Response(
            new string(' ', 16_385) + json));
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedDocumentHttpTransport.FetchAndMatchTransitionAsync(
            did, oldKey, newKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private static (byte[] OldKey, byte[] NewKey, string Json) Document(string did)
    {
        using Key old = Key.Create(SignatureAlgorithm.Ed25519);
        using Key next = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldKey = old.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] newKey = next.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        return (oldKey, newKey,
            DidWebPinnedKeyTransition.CreateTransitionDocument(did, oldKey, newKey));
    }

    private static HttpResponseMessage Response(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8,
                "application/did+ld+json")
        };

    private sealed class FakeHandler(
        Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HttpResponseMessage response = send(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }
}
