using System.Net;
using System.Text;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

/// <summary>Real signature and hostile publication acceptance for successor-only did:web.</summary>
public sealed class DidWebPinnedRetiredKeyControlVerifierTests
{
    private const string Did = "did:web:issuer.example.org";
    private static readonly Uri Audience = new("https://verifier.example.org/key-retirement");

    [Fact]
    public async Task ExactRetirementAndSuccessorProofSucceedOnlyOnce()
    {
        using Key original = Key.Create(SignatureAlgorithm.Ed25519);
        using Key successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPin = PublicKey(original);
        byte[] newPin = PublicKey(successor);
        string document = DidWebPinnedKeyRetirement.CreateRetirementDocument(Did, oldPin, newPin);
        var verifier = NewVerifier(oldPin, newPin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(successor, challenge.GetSigningInput());
        using var handler = new FakeHandler(request =>
        {
            Assert.Equal("https://issuer.example.org/.well-known/did.json",
                request.RequestUri!.AbsoluteUri);
            return Published(document);
        });
        using var http = new HttpClient(handler);

        Assert.True(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OverlapAndOldOnlyPublicationFailWithoutConsumingOriginalChallenge()
    {
        using Key original = Key.Create(SignatureAlgorithm.Ed25519);
        using Key successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPin = PublicKey(original);
        byte[] newPin = PublicKey(successor);
        string document = DidWebPinnedKeyTransition.CreateTransitionDocument(Did, oldPin, newPin);
        var verifier = NewVerifier(oldPin, newPin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(successor, challenge.GetSigningInput());
        using var handler = new FakeHandler(_ => Published(document));
        using var http = new HttpClient(handler);

        Assert.False(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
        document = new DidWebMethod().CreateDidDocument(Did, oldPin);
        Assert.False(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
        document = DidWebPinnedKeyRetirement.CreateRetirementDocument(Did, oldPin, newPin);
        Assert.True(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), signature, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OriginalSignerCannotPretendToControlSuccessorAndFailedFetchDoesNotBurnProof()
    {
        using Key original = Key.Create(SignatureAlgorithm.Ed25519);
        using Key successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPin = PublicKey(original);
        byte[] newPin = PublicKey(successor);
        string document = DidWebPinnedKeyRetirement.CreateRetirementDocument(Did, oldPin, newPin);
        var verifier = NewVerifier(oldPin, newPin);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] forged = SignatureAlgorithm.Ed25519.Sign(original, challenge.GetSigningInput());
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(successor, challenge.GetSigningInput());
        bool available = false;
        using var handler = new FakeHandler(_ => available
            ? Published(document)
            : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var http = new HttpClient(handler);

        Assert.False(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
        available = true;
        Assert.False(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), forged, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.True(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MutatingInputPinsCannotSwapTheIndependentOldAndSuccessorTrustAnchors()
    {
        using Key original = Key.Create(SignatureAlgorithm.Ed25519);
        using Key successor = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPin = PublicKey(original);
        byte[] newPin = PublicKey(successor);
        string originalDocument = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldPin, newPin);
        var verifier = NewVerifier(oldPin, newPin);
        PublicKey(attacker).CopyTo(oldPin, 0);
        PublicKey(attacker).CopyTo(newPin, 0);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(successor, challenge.GetSigningInput());
        using var handler = new FakeHandler(_ => Published(originalDocument));
        using var http = new HttpClient(handler);

        Assert.True(await verifier.TryVerifyAndConsumeAsync(challenge.GetNonce(), genuine, http,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private static byte[] PublicKey(Key key) =>
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

    private static DidWebPinnedRetiredKeyControlVerifier NewVerifier(
        byte[] oldPin, byte[] successorPin) =>
        new(Did, Audience, oldPin, successorPin, TimeProvider.System,
            capacity: 8, lifetime: TimeSpan.FromMinutes(2));

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
