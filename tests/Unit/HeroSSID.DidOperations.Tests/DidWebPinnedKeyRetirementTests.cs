using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

/// <summary>Retirement is a new, explicit step after the two-key overlap;
/// neither the old key nor its #key-1 relationship may survive publication.</summary>
public sealed class DidWebPinnedKeyRetirementTests
{
    private const string Did = "did:web:issuer.example.org:organisations:acme";

    [Fact]
    public void CreatesSuccessorOnlyDidCoreDocumentWithStableMethodIdentifier()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string document = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        using JsonDocument json = JsonDocument.Parse(document);
        JsonElement root = json.RootElement;
        Assert.Equal(Did, root.GetProperty("id").GetString());
        JsonElement methods = root.GetProperty("verificationMethod");
        Assert.Single(methods.EnumerateArray());
        Assert.Equal(Did + "#key-2", methods[0].GetProperty("id").GetString());
        Assert.Equal(Did, methods[0].GetProperty("controller").GetString());
        Assert.Equal("Ed25519VerificationKey2020",
            methods[0].GetProperty("type").GetString());
        string expectedMultibase = new DidKeyMethod().GenerateDidIdentifier(successorKey)
            ["did:key:".Length..];
        Assert.Equal(expectedMultibase,
            methods[0].GetProperty("publicKeyMultibase").GetString());
        Assert.Equal(Did + "#key-2",
            Assert.Single(root.GetProperty("authentication").EnumerateArray()).GetString());
        Assert.Equal(Did + "#key-2",
            Assert.Single(root.GetProperty("assertionMethod").EnumerateArray()).GetString());
        Assert.DoesNotContain("#key-1", document);
        Assert.Equal(5, root.EnumerateObject().Count());
    }

    [Fact]
    public void MatchesExactIndependentlyPinnedRetirementWithNonSemanticWhitespace()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string document = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        string pretty = JsonNode.Parse(document)!.ToJsonString(
            new JsonSerializerOptions { WriteIndented = true });
        Assert.True(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey, pretty));
    }

    [Fact]
    public void RejectsOldAndOverlapProfilesInsteadOfSilentlyTrustingOldKey()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey,
            new DidWebMethod().CreateDidDocument(Did, oldKey)));
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey,
            DidWebPinnedKeyTransition.CreateTransitionDocument(Did, oldKey, successorKey)));
    }

    [Fact]
    public void RejectsSubstitutionUnauthorizedDelegationAndDuplicateJsonProperties()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string original = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] wrongSuccessor = attacker.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, wrongSuccessor, original));

        JsonNode delegated = JsonNode.Parse(original)!;
        delegated["capabilityDelegation"] = new JsonArray(Did + "#key-2");
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey, delegated.ToJsonString()));

        string duplicate = original.Insert(1, "\"id\":\"" + Did + "\",");
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey, duplicate));
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey, "{\"id\":\"\\uD800\"}"));
    }

    [Fact]
    public void RejectsInvalidPinsAndDoesNotSelfEnrollSuccessor()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string original = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, oldKey, original));
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey[..31], successorKey, original));
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            "did:web:127.0.0.1", oldKey, successorKey, original));
        Assert.False(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            Did, oldKey, successorKey, new string(' ', 16_385) + original));
    }

    [Fact]
    public async Task FetchesExactRetirementAtCanonicalHttpsUriWithoutCredentials()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string original = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        int calls = 0;
        using var handler = new FakeHandler(request =>
        {
            calls++;
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("https://issuer.example.org/organisations/acme/did.json",
                request.RequestUri!.AbsoluteUri);
            Assert.Null(request.Headers.Authorization);
            return Response(original);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.True(await DidWebPinnedKeyRetirement.FetchAndMatchAsync(
            Did, oldKey, successorKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task RejectsUnpinnedRequestsBeforeNetworkAndChangedHttpsDestination()
    {
        (byte[] oldKey, byte[] successorKey) = Keys();
        string original = DidWebPinnedKeyRetirement.CreateRetirementDocument(
            Did, oldKey, successorKey);
        int calls = 0;
        using var handler = new FakeHandler(_ =>
        {
            calls++;
            return Response(original);
        });
        using var http = new HttpClient(handler, disposeHandler: false);
        Assert.False(await DidWebPinnedKeyRetirement.FetchAndMatchAsync(
            Did, oldKey, oldKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "sensitive");
        Assert.False(await DidWebPinnedKeyRetirement.FetchAndMatchAsync(
            Did, oldKey, successorKey, http,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, calls);

        using var redirectedHandler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(
                HttpMethod.Get, "https://attacker.example.org/did.json"),
            Content = new StringContent(original, Encoding.UTF8,
                "application/did+ld+json")
        });
        using var redirectedHttp = new HttpClient(redirectedHandler, disposeHandler: false);
        Assert.False(await DidWebPinnedKeyRetirement.FetchAndMatchAsync(
            Did, oldKey, successorKey, redirectedHttp,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private static (byte[] OldKey, byte[] SuccessorKey) Keys()
    {
        using Key old = Key.Create(SignatureAlgorithm.Ed25519);
        using Key next = Key.Create(SignatureAlgorithm.Ed25519);
        return (old.PublicKey.Export(KeyBlobFormat.RawPublicKey),
            next.PublicKey.Export(KeyBlobFormat.RawPublicKey));
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
