using System.Net;
using System.Text;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedPublishedKeyControlVerifierTests
{
    private const string Did = "did:web:issuer.example.org";
    private static readonly Uri Audience = new("https://verifier.example.org/prove-control");

    [Fact]
    public async Task LivePublicationAndIndependentSignerAreRequiredAndConsumedOnce()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = signer.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string document = new DidWebMethod().CreateDidDocument(Did, pin);
        var verifier = NewVerifier(pin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        int gets = 0;
        using var handler = new FakeHandler(request =>
        {
            gets++;
            Assert.Equal("https://issuer.example.org/.well-known/did.json",
                request.RequestUri!.AbsoluteUri);
            return Published(document);
        });
        using var http = new HttpClient(handler);

        Assert.True(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(2, gets);
    }

    [Fact]
    public async Task SubstitutedPublishedKeyFailsWithoutBurningOriginalChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = signer.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string published = new DidWebMethod().CreateDidDocument(
            Did, attacker.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var verifier = NewVerifier(pin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        using var handler = new FakeHandler(_ => Published(published));
        using var http = new HttpClient(handler);

        Assert.False(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));

        published = new DidWebMethod().CreateDidDocument(Did, pin);
        Assert.True(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ForgedSignatureAndFailedHttpsDoNotConsumeLiveProof()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = signer.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string document = new DidWebMethod().CreateDidDocument(Did, pin);
        var verifier = NewVerifier(pin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] forged = SignatureAlgorithm.Ed25519.Sign(attacker, challenge.GetSigningInput());
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        bool available = false;
        using var handler = new FakeHandler(_ =>
            available ? Published(document) : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var http = new HttpClient(handler);

        Assert.False(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
        available = true;
        Assert.False(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), forged, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.True(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CallerMutatingInitialPinCannotReplaceVerifierTrustAnchor()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] mutablePin = signer.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] stablePin = (byte[])mutablePin.Clone();
        var verifier = NewVerifier(mutablePin);
        attacker.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(mutablePin, 0);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        string document = new DidWebMethod().CreateDidDocument(Did, stablePin);
        using var handler = new FakeHandler(_ => Published(document));
        using var http = new HttpClient(handler);

        Assert.True(await verifier.TryVerifyAndConsumeAsync(
            challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private static DidWebPinnedPublishedKeyControlVerifier NewVerifier(byte[] pin) =>
        new(Did, Audience, pin, TimeProvider.System, capacity: 8,
            lifetime: TimeSpan.FromMinutes(2));

    private static HttpResponseMessage Published(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/did+ld+json")
        };

    private sealed class FakeHandler(
        Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HttpResponseMessage response = respond(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }
}
