using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerPinnedSuccessorAdmissionTests
{
    private static readonly Uri Audience = new("https://verifier.example/key-transition");
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IndependentPreapprovedSuccessorIsAdmittedExactlyOnce()
    {
        var oldKey = NewKey();
        var approved = NewKey();
        var clock = new FixedClock();
        var store = new InMemoryPresentationChallengeStore(clock);
        Guid tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, oldKey.Did, store);
        string proof = IssueProof(oldKey, approved, challenge.Nonce, clock);

        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string accepted));
        Assert.Equal(approved.Did, accepted);
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string replay));
        Assert.Equal(string.Empty, replay);
    }

    [Fact]
    public void GenuineButUnapprovedSuccessorCannotSpendTheApprovedChallenge()
    {
        var oldKey = NewKey();
        var approved = NewKey();
        var unauthorized = NewKey();
        var clock = new FixedClock();
        var store = new InMemoryPresentationChallengeStore(clock);
        Guid tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, oldKey.Did, store);
        // This is an authentic two-signature old-key claim; the old key alone
        // must never choose the verifier's separately pinned successor.
        string rejected = IssueProof(oldKey, unauthorized, challenge.Nonce, clock);
        string allowed = IssueProof(oldKey, approved, challenge.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            rejected, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string invalid));
        Assert.Equal(string.Empty, invalid);
        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            allowed, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string accepted));
        Assert.Equal(approved.Did, accepted);
    }

    [Fact]
    public void ForeignTenantAndWrongPolicyCannotSpendTheChallenge()
    {
        var oldKey = NewKey();
        var approved = NewKey();
        var foreign = NewKey();
        var clock = new FixedClock();
        var store = new InMemoryPresentationChallengeStore(clock);
        Guid tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, oldKey.Did, store);
        string proof = IssueProof(oldKey, approved, challenge.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            Guid.NewGuid(), store, clock, out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, foreign.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, new Uri("https://other.example/key-transition"),
            challenge.Nonce, tenant, store, clock, out _));
        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string accepted));
        Assert.Equal(approved.Did, accepted);
    }

    [Fact]
    public void ExpiredProofCannotReleasePinnedSuccessorOrBeReplayed()
    {
        var oldKey = NewKey();
        var approved = NewKey();
        var clock = new FixedClock();
        var store = new InMemoryPresentationChallengeStore(clock);
        Guid tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, oldKey.Did, store);
        string proof = IssueProof(oldKey, approved, challenge.Nonce, clock);

        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
            proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
            tenant, store, clock, out string expired));
        Assert.Equal(string.Empty, expired);
    }

    [Fact]
    public void ConcurrentPinnedAdmissionAcceptsOnlyOneContender()
    {
        var oldKey = NewKey();
        var approved = NewKey();
        var clock = new FixedClock();
        var store = new InMemoryPresentationChallengeStore(clock);
        Guid tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, oldKey.Did, store);
        string proof = IssueProof(oldKey, approved, challenge.Nonce, clock);
        int accepted = 0;

        Parallel.For(0, 24, _ =>
        {
            if (IssuerKeySuccessorAttestation.TryVerifyAndConsumePinnedSuccessor(
                proof, oldKey.Did, approved.Did, Audience, challenge.Nonce,
                tenant, store, clock, out string successor))
            {
                Assert.Equal(approved.Did, successor);
                Interlocked.Increment(ref accepted);
            }
        });

        Assert.Equal(1, accepted);
    }

    private static string IssueProof(
        (string Did, byte[] Seed) oldKey,
        (string Did, byte[] Seed) newKey,
        string nonce, TimeProvider clock) =>
        IssuerKeySuccessorAttestation.Create(
            oldKey.Did, newKey.Did, oldKey.Seed, newKey.Seed,
            Audience, nonce, clock);

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] didBytes = new byte[34];
        didBytes[0] = 0xed;
        didBytes[1] = 0x01;
        publicKey.CopyTo(didBytes, 2);
        return ("did:key:z" + SimpleBase.Base58.Bitcoin.Encode(didBytes),
            key.Export(KeyBlobFormat.RawPrivateKey));
    }

    private sealed class FixedClock : TimeProvider
    {
        private DateTimeOffset _now = Now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan time) => _now = _now.Add(time);
    }
}
