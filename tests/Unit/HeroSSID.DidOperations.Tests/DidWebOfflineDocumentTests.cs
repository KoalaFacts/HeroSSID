using System.Text.Json;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

// Offline document generation is not proof that the HTTPS domain serves this
// document or that an independent did:web resolver trusts the published key.
public sealed class DidWebOfflineDocumentTests
{
    [Fact]
    public void DomainAndPathProduceAnExplicitPublishableDidDocument()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var options = new Dictionary<string, object>
        {
            ["domain"] = "issuer.example.com",
            ["path"] = "organizations/acme"
        };

        var method = new DidWebMethod();
        string did = method.GenerateDidIdentifier(publicKey, options);
        Assert.Equal("did:web:issuer.example.com:organizations:acme", did);
        Assert.True(method.IsValid(did));
        Assert.Equal("https://issuer.example.com/organizations/acme/did.json",
            DidWebMethod.GetDocumentUri(did).AbsoluteUri);

        using JsonDocument json = JsonDocument.Parse(
            method.CreateDidDocument(did, publicKey, options));
        JsonElement root = json.RootElement;
        Assert.Equal(did, root.GetProperty("id").GetString());
        Assert.Contains(root.GetProperty("@context").EnumerateArray(),
            item => item.GetString() == "https://www.w3.org/ns/did/v1");

        JsonElement verification = Assert.Single(
            root.GetProperty("verificationMethod").EnumerateArray());
        string methodId = did + "#key-1";
        Assert.Equal(methodId, verification.GetProperty("id").GetString());
        Assert.Equal(did, verification.GetProperty("controller").GetString());
        Assert.Equal("Ed25519VerificationKey2020", verification.GetProperty("type").GetString());
        string multibase = verification.GetProperty("publicKeyMultibase").GetString()!;
        Assert.StartsWith("z", multibase, StringComparison.Ordinal);
        byte[] prefixed = SimpleBase.Base58.Bitcoin.Decode(multibase.AsSpan(1));
        Assert.Equal(34, prefixed.Length);
        Assert.Equal((byte)0xed, prefixed[0]);
        Assert.Equal((byte)0x01, prefixed[1]);
        Assert.Equal(publicKey, prefixed.AsSpan(2).ToArray());
        Assert.Equal(methodId, root.GetProperty("authentication")[0].GetString());
        Assert.Equal(methodId, root.GetProperty("assertionMethod")[0].GetString());
        Assert.False(root.TryGetProperty("keyAgreement", out _));
        Assert.False(root.TryGetProperty("capabilityDelegation", out _));
    }

    [Fact]
    public void RootDocumentHasStandardWellKnownIdentifier()
    {
        byte[] publicKey = NewPublicKey();
        var method = new DidWebMethod();
        var options = new Dictionary<string, object> { ["domain"] = "example.org" };
        string did = method.GenerateDidIdentifier(publicKey, options);
        Assert.Equal("did:web:example.org", did);
        Assert.Equal("https://example.org/.well-known/did.json",
            DidWebMethod.GetDocumentUri(did).AbsoluteUri);
        using JsonDocument json = JsonDocument.Parse(
            method.CreateDidDocument(did, publicKey, options));
        Assert.Equal(did, json.RootElement.GetProperty("id").GetString());
    }

    [Theory]
    [InlineData("did:web:example.org:..:private")]
    [InlineData("did:web:example.org:%2F:secret")]
    [InlineData("did:web:example.org::admin")]
    [InlineData("did:web:example.org/admin")]
    [InlineData("did:web:example.org:foo?bar")]
    [InlineData("did:web:localhost")]
    [InlineData("did:web:127.0.0.1")]
    [InlineData("did:web:example.org:")]
    [InlineData("did:web:EXAMPLE.org")]
    [InlineData("did:web:example.org:users:..")]
    public void RejectsAmbiguousOrUnsafeIdentifiers(string did)
    {
        var method = new DidWebMethod();
        Assert.False(method.IsValid(did));
        Assert.Throws<ArgumentException>(() => DidWebMethod.GetDocumentUri(did));
        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(did, NewPublicKey()));
    }

    [Fact]
    public void RefusesMissingOrMismatchedDomainAndKeyMaterial()
    {
        var method = new DidWebMethod();
        byte[] publicKey = NewPublicKey();
        Assert.Throws<ArgumentException>(() => method.GenerateDidIdentifier(
            publicKey, new Dictionary<string, object>()));
        Assert.Throws<ArgumentException>(() => method.GenerateDidIdentifier(
            publicKey, new Dictionary<string, object> { ["domain"] = "example.org",
                ["path"] = "../admin" }));
        Assert.Throws<ArgumentException>(() => method.GenerateDidIdentifier(
            publicKey.AsSpan(1).ToArray(),
            new Dictionary<string, object> { ["domain"] = "example.org" }));
        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(
            "did:web:example.org", publicKey.AsSpan(1).ToArray()));
        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(
            "did:web:example.org", publicKey,
            new Dictionary<string, object> { ["domain"] = "other.example.org" }));
    }

    private static byte[] NewPublicKey()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }
}
