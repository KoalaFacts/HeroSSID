using System.Threading;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerGuardianRecoveryChallengeTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Audience = new("https://relying.example/issuer-recovery");

    [Fact]
    public void SignedIndependentQuorumSucceedsOnlyOnceAndDisclosesAfterConsumption()
    {
        var f = new Fixture();
        var (challenge, proof) = f.IssueValidProof();

        Assert.True(f.Check(proof, challenge.Nonce, out string successor));
        Assert.Equal(f.Successor.Did, successor);
        Assert.False(f.Check(proof, challenge.Nonce, out string replaySuccessor));
        Assert.Equal(string.Empty, replaySuccessor);
    }

    [Fact]
    public void WrongTenantAudienceOrOldIssuerCannotSpendRecoveryNonce()
    {
        var f = new Fixture();
        var (challenge, proof) = f.IssueValidProof();
        Assert.False(f.Check(proof, challenge.Nonce, out string wrongTenant,
            tenantId: Guid.NewGuid()));
        Assert.Equal(string.Empty, wrongTenant);
        Assert.False(f.Check(proof, challenge.Nonce, out string wrongAudience,
            audience: new Uri("https://other.example/issuer-recovery")));
        Assert.Equal(string.Empty, wrongAudience);
        Assert.False(f.Check(proof, challenge.Nonce, out string wrongIssuer,
            previousIssuerDid: NewKey().Did));
        Assert.Equal(string.Empty, wrongIssuer);
        Assert.True(f.Check(proof, challenge.Nonce, out string successor));
        Assert.Equal(f.Successor.Did, successor);
    }

    [Fact]
    public void OrdinaryPresentationNonceCannotBeUpgradedIntoRecoveryAuthority()
    {
        var f = new Fixture();
        var presentation = f.Store.Issue(f.TenantId, Audience.AbsoluteUri,
            f.Previous.Did, TimeSpan.FromMinutes(2));
        string proof = f.Proof(presentation.Nonce);
        Assert.False(f.Check(proof, presentation.Nonce, out string successor));
        Assert.Equal(string.Empty, successor);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, presentation.Nonce));
    }

    [Fact]
    public void ForgedSecondGuardianFailsWithoutConsumingTheGenuineChallenge()
    {
        var f = new Fixture();
        var challenge = IssuerGuardianRecoveryChallenges.Issue(f.Store, f.TenantId,
            f.Previous.Did, Audience);
        var attacker = NewKey();
        string invalid = IssuerGuardianRecovery.Create(f.Previous.Did,
            f.Successor.Did, f.Successor.Seed,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [f.GuardianOne.Did] = f.GuardianOne.Seed,
                [attacker.Did] = attacker.Seed
            }, Audience, challenge.Nonce, f.Clock);

        Assert.False(f.Check(invalid, challenge.Nonce, out string rejected));
        Assert.Equal(string.Empty, rejected);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));
        Assert.True(f.Check(f.Proof(challenge.Nonce), challenge.Nonce, out string accepted));
        Assert.Equal(f.Successor.Did, accepted);
    }

    [Fact]
    public void ExpiredRecoveryChallengeRejectsStillCryptographicallyValidProof()
    {
        var f = new Fixture();
        var challenge = IssuerGuardianRecoveryChallenges.Issue(f.Store,
            f.TenantId, f.Previous.Did, Audience, TimeSpan.FromSeconds(5));
        string proof = f.Proof(challenge.Nonce);
        f.Clock.Advance(TimeSpan.FromSeconds(5));

        Assert.False(f.Check(proof, challenge.Nonce, out string successor));
        Assert.Equal(string.Empty, successor);
    }

    [Fact]
    public void ConcurrentReplicasSharingStoreAcceptOnlyOneRecovery()
    {
        var f = new Fixture();
        var (challenge, proof) = f.IssueValidProof();
        int accepted = 0;
        Parallel.For(0, 24, _ =>
        {
            if (f.Check(proof, challenge.Nonce, out string successor))
            {
                Assert.Equal(f.Successor.Did, successor);
                Interlocked.Increment(ref accepted);
            }
        });
        Assert.Equal(1, accepted);
    }

    [Fact]
    public void FailedAtomicConsumptionDoesNotExposeAValidSuccessor()
    {
        var f = new Fixture();
        var (challenge, proof) = f.IssueValidProof();
        var refusingStore = new RefusingConsumeStore(f.Store);
        bool accepted = IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
            refusingStore, f.TenantId, proof, f.Previous.Did,
            [f.GuardianOne.Did, f.GuardianTwo.Did], 2,
            Audience, challenge.Nonce, f.Clock, out string successor);
        Assert.False(accepted);
        Assert.Equal(string.Empty, successor);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));
    }

    [Fact]
    public void IncidentCancellationRejectsOtherwiseValidGuardianQuorum()
    {
        var fixture = new Fixture();
        var (challenge, proof) = fixture.IssueValidProof();

        Assert.True(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, fixture.TenantId, fixture.Previous.Did, Audience,
            challenge.Nonce));
        Assert.False(fixture.Check(proof, challenge.Nonce, out string recovered));
        Assert.Equal(string.Empty, recovered);
        Assert.False(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, fixture.TenantId, fixture.Previous.Did, Audience,
            challenge.Nonce));
    }

    [Fact]
    public void IncorrectTenantOldIssuerAndAudienceCannotCancelRecovery()
    {
        var fixture = new Fixture();
        var (challenge, proof) = fixture.IssueValidProof();

        Assert.False(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, Guid.NewGuid(), fixture.Previous.Did, Audience,
            challenge.Nonce));
        Assert.False(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, fixture.TenantId, NewKey().Did, Audience,
            challenge.Nonce));
        Assert.False(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, fixture.TenantId, fixture.Previous.Did,
            new Uri("https://other.example/recovery"), challenge.Nonce));

        Assert.True(fixture.Check(proof, challenge.Nonce, out string recovered));
        Assert.Equal(fixture.Successor.Did, recovered);
    }

    [Fact]
    public void CancellingRecoveryCannotSpendAnOrdinaryPresentationChallenge()
    {
        var fixture = new Fixture();
        var ordinary = fixture.Store.Issue(fixture.TenantId, Audience.AbsoluteUri,
            fixture.Previous.Did, TimeSpan.FromMinutes(2));

        Assert.False(IssuerGuardianRecoveryChallenges.TryCancel(
            fixture.Store, fixture.TenantId, fixture.Previous.Did, Audience,
            ordinary.Nonce));
        Assert.NotNull(fixture.Store.Find(
            fixture.TenantId, Audience.AbsoluteUri, ordinary.Nonce));
        Assert.True(fixture.Store.TryConsume(
            fixture.TenantId, Audience.AbsoluteUri, ordinary.Nonce));
    }

    [Fact]
    public void ConcurrentCancellationOfOneRecoveryChallengeHasExactlyOneWinner()
    {
        var fixture = new Fixture();
        var (challenge, proof) = fixture.IssueValidProof();
        int cancelled = 0;

        Parallel.For(0, 24, _ =>
        {
            if (IssuerGuardianRecoveryChallenges.TryCancel(
                fixture.Store, fixture.TenantId, fixture.Previous.Did, Audience,
                challenge.Nonce))
            {
                Interlocked.Increment(ref cancelled);
            }
        });

        Assert.Equal(1, cancelled);
        Assert.False(fixture.Check(proof, challenge.Nonce, out string candidate));
        Assert.Equal(string.Empty, candidate);
    }

    private sealed class Fixture
    {
        public FixedClock Clock { get; } = new(Now);
        public Guid TenantId { get; } = Guid.NewGuid();
        public (string Did, byte[] Seed) Previous { get; } = NewKey();
        public (string Did, byte[] Seed) Successor { get; } = NewKey();
        public (string Did, byte[] Seed) GuardianOne { get; } = NewKey();
        public (string Did, byte[] Seed) GuardianTwo { get; } = NewKey();
        public InMemoryPresentationChallengeStore Store { get; }

        public Fixture() => Store = new InMemoryPresentationChallengeStore(Clock);

        public (PresentationChallenge Challenge, string Proof) IssueValidProof()
        {
            var challenge = IssuerGuardianRecoveryChallenges.Issue(
                Store, TenantId, Previous.Did, Audience);
            return (challenge, Proof(challenge.Nonce));
        }

        public string Proof(string nonce) => IssuerGuardianRecovery.Create(
            Previous.Did, Successor.Did, Successor.Seed,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [GuardianOne.Did] = GuardianOne.Seed,
                [GuardianTwo.Did] = GuardianTwo.Seed
            }, Audience, nonce, Clock);

        public bool Check(string proof, string nonce, out string successor,
            Guid? tenantId = null, Uri? audience = null, string? previousIssuerDid = null) =>
            IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
                Store, tenantId ?? TenantId, proof, previousIssuerDid ?? Previous.Did,
                [GuardianOne.Did, GuardianTwo.Did], 2, audience ?? Audience,
                nonce, Clock, out successor);
    }

    private sealed class RefusingConsumeStore(IPresentationChallengeStore inner)
        : IPresentationChallengeStore
    {
        public PresentationChallenge Issue(Guid verifierTenantId, string audience,
            string trustedIssuerDid, TimeSpan? lifetime = null) =>
            inner.Issue(verifierTenantId, audience, trustedIssuerDid, lifetime);

        public PresentationChallenge? Find(Guid verifierTenantId, string audience,
            string nonce) => inner.Find(verifierTenantId, audience, nonce);

        public bool TryConsume(Guid verifierTenantId, string audience, string nonce) => false;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        publicKey.CopyTo(bytes, 2);
        return ("did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes),
            key.Export(KeyBlobFormat.RawPrivateKey));
    }
}
