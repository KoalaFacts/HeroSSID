using System.Text.Json.Nodes;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPublishedKeyMatchTests
{
    [Fact]
    public void MatchesOriginalAndCompactPublicationWithIndependentlyPinnedKey()
    {
        (string did, byte[] expectedKey, string json) = CreateDocument();
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(did, expectedKey, json));
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, expectedKey, JsonNode.Parse(json)!.ToJsonString()));
    }

    [Fact]
    public void AcceptsPathBasedPublishedDocumentOnlyUnderExactPinnedDid()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var method = new DidWebMethod();
        var options = new Dictionary<string, object>
        {
            ["domain"] = "issuer.example.org", ["path"] = "organisations/acme"
        };
        string did = method.GenerateDidIdentifier(publicKey, options);
        string json = method.CreateDidDocument(did, publicKey, options);

        Assert.Equal("https://issuer.example.org/organisations/acme/did.json",
            DidWebMethod.GetDocumentUri(did).AbsoluteUri);
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(did, publicKey, json));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            "did:web:issuer.example.org", publicKey, json));
    }

    [Fact]
    public void RejectsDocumentFromAnotherKeyEvenWhenDidAndHostAreTheSame()
    {
        (string did, byte[] expectedKey, _) = CreateDocument();
        using Key other = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] replacementKey = other.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string forged = new DidWebMethod().CreateDidDocument(did, replacementKey);
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(did, expectedKey, forged));
    }

    [Fact]
    public void RejectsForgedAuthenticationAndAssertionMethodReferences()
    {
        (string did, byte[] key, string json) = CreateDocument();
        JsonNode changed = JsonNode.Parse(json)!;
        changed["authentication"]![0] = did + "#attacker";
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, changed.ToJsonString()));

        changed = JsonNode.Parse(json)!;
        changed["assertionMethod"]![0] = did + "#attacker";
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, changed.ToJsonString()));
    }

    [Fact]
    public void RejectsDifferentControllerOrUnrequestedDelegationCapabilities()
    {
        (string did, byte[] key, string json) = CreateDocument();
        JsonNode changed = JsonNode.Parse(json)!;
        changed["verificationMethod"]![0]!["controller"] = "did:web:attacker.example.org";
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, changed.ToJsonString()));

        changed = JsonNode.Parse(json)!;
        changed["capabilityDelegation"] = new JsonArray(did + "#key-1");
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, changed.ToJsonString()));
    }

    [Fact]
    public void RejectsMalformedDuplicateOrExcessivelyLargeDocuments()
    {
        (string did, byte[] key, string json) = CreateDocument();
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(did, key, "{"));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, json + "  true"));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, json.Replace("\"id\":", "\"id\":\"did:web:attacker.example.org\", \"id\":",
                StringComparison.Ordinal)));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, new string(' ', 16385)));
    }

    [Fact]
    public void RejectsLoneSurrogateEscapesInJsonNamesAndValuesWithoutThrowing()
    {
        (string did, byte[] key, string json) = CreateDocument();

        // JsonDocument can parse these escape tokens and defer the failure
        // until property.Name or GetString() performs actual unescaping.
        string malformedName = json.Replace(
            "\"id\":", "\"\\uD800\":", StringComparison.Ordinal);
        string malformedValue = json.Replace(
            "\"id\": \"did:web:issuer.example.org\"",
            "\"id\": \"\\uD800\"", StringComparison.Ordinal);

        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, malformedName));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, key, malformedValue));
    }

    private static (string Did, byte[] PublicKey, string Json) CreateDocument()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var method = new DidWebMethod();
        const string did = "did:web:issuer.example.org";
        return (did, publicKey, method.CreateDidDocument(did, publicKey));
    }
}
