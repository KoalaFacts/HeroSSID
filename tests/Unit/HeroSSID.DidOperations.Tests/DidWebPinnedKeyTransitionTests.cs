using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedKeyTransitionTests
{
    [Fact]
    public void CreatesTwoKeyDidCoreDocumentForStableDidWebLocation()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        const string did = "did:web:issuer.example.org:organisations:acme";
        string json = DidWebPinnedKeyTransition.CreateTransitionDocument(did, oldKey, newKey);
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        Assert.Equal("https://issuer.example.org/organisations/acme/did.json",
            DidWebMethod.GetDocumentUri(did).AbsoluteUri);
        Assert.Equal(did, root.GetProperty("id").GetString());
        Assert.Equal("https://www.w3.org/ns/did/v1",
            root.GetProperty("@context")[0].GetString());
        Assert.Equal(2, root.GetProperty("verificationMethod").GetArrayLength());
        Assert.Equal(did + "#key-1",
            root.GetProperty("verificationMethod")[0].GetProperty("id").GetString());
        Assert.Equal(did + "#key-2",
            root.GetProperty("verificationMethod")[1].GetProperty("id").GetString());
        Assert.Equal(did + "#key-1",
            root.GetProperty("authentication")[0].GetString());
        Assert.Equal(did + "#key-2",
            root.GetProperty("assertionMethod")[1].GetString());
    }

    [Fact]
    public void VerifiesBothPrePinnedKeysAcrossJsonWhitespaceAndPropertyOrder()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        const string did = "did:web:issuer.example.org";
        string document = DidWebPinnedKeyTransition.CreateTransitionDocument(
            did, oldKey, newKey);
        string compact = JsonNode.Parse(document)!.ToJsonString();

        Assert.True(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, document));
        Assert.True(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, compact));
        // The existing single-key profile remains independently strict.
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            did, oldKey, document));
    }

    [Fact]
    public void RejectsReorderedOrSubstitutedKeysEvenForTheSameDid()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        (byte[] replacement, _) = Keys();
        const string did = "did:web:issuer.example.org";
        string document = DidWebPinnedKeyTransition.CreateTransitionDocument(
            did, oldKey, newKey);

        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, newKey, oldKey, document));
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, replacement, document));
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            "did:web:another.example.org", oldKey, newKey, document));
    }

    [Fact]
    public void RejectsAlteredControllerRelationshipAndExtraDelegation()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        const string did = "did:web:issuer.example.org";
        string original = DidWebPinnedKeyTransition.CreateTransitionDocument(
            did, oldKey, newKey);

        JsonNode changed = JsonNode.Parse(original)!;
        changed["verificationMethod"]![1]!["controller"] = "did:web:attacker.example.org";
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, changed.ToJsonString()));

        changed = JsonNode.Parse(original)!;
        changed["assertionMethod"]![1] = did + "#untrusted";
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, changed.ToJsonString()));

        changed = JsonNode.Parse(original)!;
        changed["capabilityDelegation"] = new JsonArray(did + "#key-2");
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, changed.ToJsonString()));
    }

    [Fact]
    public void RejectsDuplicateMembersAndMalformedJson()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        const string did = "did:web:issuer.example.org";
        string original = DidWebPinnedKeyTransition.CreateTransitionDocument(
            did, oldKey, newKey);

        string duplicate = original.Replace(
            "\"verificationMethod\":", "\"verificationMethod\":[],\"verificationMethod\":",
            StringComparison.Ordinal);
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, duplicate));
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, "{"));
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, new string(' ', 16_385)));
    }

    [Fact]
    public void RejectsMalformedUnicodeWithoutThrowing()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        const string did = "did:web:issuer.example.org";
        string original = DidWebPinnedKeyTransition.CreateTransitionDocument(
            did, oldKey, newKey);
        string malformed = original.Replace(
            "\"controller\":", "\"\\uD800\":", StringComparison.Ordinal);
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            did, oldKey, newKey, malformed));
    }

    [Fact]
    public void RejectsSameOrInvalidKeysAndInvalidDids()
    {
        (byte[] oldKey, byte[] newKey) = Keys();
        Assert.Throws<ArgumentException>(() =>
            DidWebPinnedKeyTransition.CreateTransitionDocument(
                "did:web:issuer.example.org", oldKey, oldKey));
        Assert.Throws<ArgumentException>(() =>
            DidWebPinnedKeyTransition.CreateTransitionDocument(
                "did:web:issuer.example.org", oldKey[..31], newKey));
        Assert.Throws<ArgumentException>(() =>
            DidWebPinnedKeyTransition.CreateTransitionDocument(
                "did:web:127.0.0x1", oldKey, newKey));
    }

    private static (byte[] OldKey, byte[] NewKey) Keys()
    {
        using Key old = Key.Create(SignatureAlgorithm.Ed25519);
        using Key next = Key.Create(SignatureAlgorithm.Ed25519);
        return (old.PublicKey.Export(KeyBlobFormat.RawPublicKey),
            next.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }
}
