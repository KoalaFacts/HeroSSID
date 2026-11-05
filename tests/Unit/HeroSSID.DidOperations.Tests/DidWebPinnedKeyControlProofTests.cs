using System.Security.Cryptography;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedKeyControlProofTests
{
    private const string Did = "did:web:issuer.example.org";
    private static readonly Uri Audience = new("https://verifier.example.org/issuer-key-check");
    private static readonly DateTimeOffset Issued = new(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IndependentlySignedSuccessorChallengeVerifiesAgainstItsPinnedEd25519Key()
    {
        using Key successorSigner = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = successorSigner.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        DateTimeOffset expires = Issued.AddMinutes(3);
        byte[] input = DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-2", Audience, nonce, Issued, expires);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(successorSigner, input);

        Assert.True(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", Audience, nonce, Issued, expires,
            Issued.AddMinutes(1), pin, signature));
    }

    [Fact]
    public void RejectsRebindingForeignKeyOrStaleSignedEvidenceWithoutReleasingTrust()
    {
        using Key successorSigner = Key.Create(SignatureAlgorithm.Ed25519);
        using Key alienSigner = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = successorSigner.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] alienPin = alienSigner.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        DateTimeOffset expires = Issued.AddMinutes(3);
        byte[] input = DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-2", Audience, nonce, Issued, expires);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(successorSigner, input);

        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", Audience, nonce, Issued, expires,
            Issued.AddMinutes(1), alienPin, signature));
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            "did:web:other.example.org", "#key-2", Audience, nonce, Issued, expires,
            Issued.AddMinutes(1), pin, signature));
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-1", Audience, nonce, Issued, expires,
            Issued.AddMinutes(1), pin, signature));
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", new Uri("https://other-verifier.example.org/issuer-key-check"),
            nonce, Issued, expires, Issued.AddMinutes(1), pin, signature));
        byte[] differentNonce = (byte[])nonce.Clone();
        differentNonce[0] ^= 1;
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", Audience, differentNonce, Issued, expires,
            Issued.AddMinutes(1), pin, signature));
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", Audience, nonce, Issued, expires,
            Issued.AddMinutes(3), pin, signature));
        Assert.False(DidWebPinnedKeyControlProof.TryVerify(
            Did, "#key-2", Audience, nonce, Issued, expires,
            Issued.AddSeconds(-1), pin, signature));
    }

    [Fact]
    public void RefusesInvalidDnsMethodAudienceNonceOrLifetimeBeforeSigning()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        Assert.Throws<ArgumentException>(() => DidWebPinnedKeyControlProof.CreateSigningInput(
            "did:key:abc", "#key-2", Audience, nonce, Issued, Issued.AddMinutes(3)));
        Assert.Throws<ArgumentException>(() => DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-3", Audience, nonce, Issued, Issued.AddMinutes(3)));
        Assert.Throws<ArgumentException>(() => DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-2", new Uri("http://verifier.example.org/issuer-key-check"),
            nonce, Issued, Issued.AddMinutes(3)));
        Assert.Throws<ArgumentException>(() => DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-2", Audience, nonce[..16], Issued, Issued.AddMinutes(3)));
        Assert.Throws<ArgumentException>(() => DidWebPinnedKeyControlProof.CreateSigningInput(
            Did, "#key-2", Audience, nonce, Issued, Issued.AddMinutes(10)));
    }
}
