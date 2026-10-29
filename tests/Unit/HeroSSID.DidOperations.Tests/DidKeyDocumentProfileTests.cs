using System.Text.Json;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

// This is a did:key/Ed25519VerificationKey2020 profile contract, not an
// independent wallet or DID resolver interoperability certification.
#pragma warning disable CA1707 // xUnit method naming convention
public sealed class DidKeyDocumentProfileTests
{
    private const string KnownDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    [Fact]
    public void KnownDidKeyVector_PublishesMatchingMulticodecAndAssertionMethod()
    {
        string knownSuffix = KnownDid.Substring("did:key:z".Length);
        byte[] prefixedKey = SimpleBase.Base58.Bitcoin.Decode(knownSuffix);
        Assert.Equal(34, prefixedKey.Length);
        Assert.Equal((byte)0xed, prefixedKey[0]);
        Assert.Equal((byte)0x01, prefixedKey[1]);
        byte[] publicKey = prefixedKey.AsSpan(2).ToArray();

        DidKeyMethod method = new DidKeyMethod();
        Assert.Equal(KnownDid, method.GenerateDidIdentifier(publicKey));

        using JsonDocument document = JsonDocument.Parse(method.CreateDidDocument(KnownDid, publicKey));
        AssertProfile(document.RootElement, KnownDid, publicKey);
    }

    [Fact]
    public void FreshRealEd25519Key_PublishesSameKeyAndVerificationRelationships()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        DidKeyMethod method = new DidKeyMethod();
        string did = method.GenerateDidIdentifier(publicKey);

        using JsonDocument document = JsonDocument.Parse(method.CreateDidDocument(did, publicKey));
        AssertProfile(document.RootElement, did, publicKey);
    }

    [Fact]
    public void DocumentCreation_RejectsDifferentPublicKeyForValidDid()
    {
        byte[] firstKey = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        byte[] secondKey = Enumerable.Range(2, 32).Select(value => (byte)value).ToArray();
        DidKeyMethod method = new DidKeyMethod();
        string did = method.GenerateDidIdentifier(firstKey);

        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(did, secondKey));
    }

    [Fact]
    public void DocumentCreation_RejectsInvalidKeyLengthAndMalformedDid()
    {
        byte[] key = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        DidKeyMethod method = new DidKeyMethod();
        string did = method.GenerateDidIdentifier(key);

        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(did, key.AsSpan(1).ToArray()));
        Assert.Throws<ArgumentException>(() => method.CreateDidDocument(did + "extra", key));
        Assert.Throws<ArgumentException>(() => method.CreateDidDocument("did:web:example.com", key));
    }

    private static void AssertProfile(JsonElement document, string did, byte[] publicKey)
    {
        Assert.Equal(did, document.GetProperty("id").GetString());
        JsonElement verificationMethods = document.GetProperty("verificationMethod");
        Assert.Equal(1, verificationMethods.GetArrayLength());
        JsonElement verificationMethod = verificationMethods[0];

        string expectedMultibase = did["did:key:".Length..];
        string expectedMethodId = did + "#" + expectedMultibase;

        Assert.Equal(expectedMethodId, verificationMethod.GetProperty("id").GetString());
        Assert.Equal(did, verificationMethod.GetProperty("controller").GetString());
        Assert.Equal("Ed25519VerificationKey2020", verificationMethod.GetProperty("type").GetString());
        Assert.Equal(expectedMultibase, verificationMethod.GetProperty("publicKeyMultibase").GetString());

        string encodedKey = expectedMultibase.Substring(1);
        byte[] decoded = SimpleBase.Base58.Bitcoin.Decode(encodedKey);
        Assert.Equal(34, decoded.Length);
        Assert.Equal((byte)0xed, decoded[0]);
        Assert.Equal((byte)0x01, decoded[1]);
        Assert.Equal(publicKey, decoded.AsSpan(2).ToArray());

        Assert.Equal(JsonValueKind.Array, document.GetProperty("authentication").ValueKind);
        Assert.Equal(expectedMethodId, document.GetProperty("authentication")[0].GetString());
        Assert.Equal(JsonValueKind.Array, document.GetProperty("assertionMethod").ValueKind);
        Assert.Equal(expectedMethodId, document.GetProperty("assertionMethod")[0].GetString());

        // Do not claim X25519 key agreement or capability relationships.
        Assert.False(document.TryGetProperty("keyAgreement", out _));
        Assert.False(document.TryGetProperty("capabilityInvocation", out _));
        Assert.False(document.TryGetProperty("capabilityDelegation", out _));
        Assert.False(document.TryGetProperty("service", out _));
        Assert.False(verificationMethod.TryGetProperty("publicKeyBase58", out _));
    }
}
#pragma warning restore CA1707
