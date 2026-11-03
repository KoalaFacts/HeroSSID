using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpJwtVcJsonRequestObjectStoreTests
{
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Callback = new("https://verifier.example/callback");
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");

    [Fact]
    public void GenuinePublishedRequestIsByteIdenticalAndExpiresWhenChallengeIsConsumed()
    {
        var clock = new Clock();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var verifier = Identity();
        var issuer = Identity();
        string audience = "decentralized_identifier:" + verifier.Did;
        var challenge = challenges.Issue(tenant, audience, issuer.Did, TimeSpan.FromMinutes(2));
        string signed = SignedRequest(challenge, verifier, clock);
        var host = new OpenId4VpJwtVcJsonRequestObjectStore(challenges, clock);

        string reference = host.Publish(tenant, signed, verifier.Did, Callback, CredentialType, Context);
        Assert.Equal(43, reference.Length);
        Assert.All(reference, character => Assert.True(
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        Assert.True(host.TryGet(reference, out string first));
        Assert.Equal(signed, first);
        Assert.True(host.TryGet(reference, out string second));
        Assert.Equal(first, second);

        Assert.True(challenges.TryConsume(tenant, audience, challenge.Nonce));
        Assert.False(host.TryGet(reference, out string unavailable));
        Assert.Equal(string.Empty, unavailable);
    }

    [Fact]
    public void AForgerCannotPublishAndUnknownOrExpiredReferencesReturnNoRequest()
    {
        var clock = new Clock();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var verifier = Identity();
        var issuer = Identity();
        var attacker = Identity();
        var challenge = challenges.Issue(tenant,
            "decentralized_identifier:" + verifier.Did, issuer.Did, TimeSpan.FromMinutes(2));
        string signed = SignedRequest(challenge, verifier, clock);
        var host = new OpenId4VpJwtVcJsonRequestObjectStore(challenges, clock);

        Assert.Throws<ArgumentException>(() =>
            host.Publish(tenant, signed, attacker.Did, Callback, CredentialType, Context));
        Assert.Throws<ArgumentException>(() =>
            host.Publish(Guid.NewGuid(), signed, verifier.Did, Callback, CredentialType, Context));
        Assert.False(host.TryGet(new string('A', 43), out _));
        string reference = host.Publish(tenant, signed, verifier.Did, Callback, CredentialType, Context);
        clock.Advance(TimeSpan.FromMinutes(3));
        Assert.False(host.TryGet(reference, out string expired));
        Assert.Equal(string.Empty, expired);
    }

    [Fact]
    public void BoundedReservationsRejectBeforeDurableIssuanceAndReleaseOnFailure()
    {
        var clock = new Clock();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var host = new OpenId4VpJwtVcJsonRequestObjectStore(challenges, clock);

        string[] references = Enumerable.Range(0, 256)
            .Select(_ => host.Reserve()).ToArray();
        Assert.Equal(256, references.Distinct(StringComparer.Ordinal).Count());
        Assert.All(references, reference => Assert.Equal(43, reference.Length));
        Assert.All(references, reference => Assert.False(host.TryGet(reference, out _)));
        Assert.Throws<InvalidOperationException>(() => host.Reserve());

        // The pending reservations have not used the independent challenge store.
        var verifier = Identity();
        var issuer = Identity();
        Guid tenant = Guid.NewGuid();
        var pending = challenges.Issue(tenant,
            "decentralized_identifier:" + verifier.Did, issuer.Did);
        Assert.NotNull(challenges.Find(tenant, pending.Audience, pending.Nonce));

        string reference = references[0];
        host.ReleaseReservation(reference);
        Assert.False(host.TryGet(reference, out _));
        Assert.Equal(43, host.Reserve().Length);
        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(43, host.Reserve().Length);
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private static string SignedRequest(PresentationChallenge challenge,
        (byte[] Seed, string Did) verifier, TimeProvider clock) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, verifier.Did, verifier.Seed, Callback, CredentialType, Context, clock);

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 3, 5, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }
}
