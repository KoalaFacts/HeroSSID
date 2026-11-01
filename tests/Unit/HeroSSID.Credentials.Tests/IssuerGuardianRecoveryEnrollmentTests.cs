using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerGuardianRecoveryEnrollmentTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 0, 0, 0, TimeSpan.Zero);
    private static readonly Uri Audience = new("https://verifier.example/guardian-recovery");

    [Fact]
    public void PreviouslyPinnedEnrollmentEnablesRecoveryOnlyOnce()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();
        var challenge = f.Issue(enrollment, pin);
        string evidence = f.Proof(challenge.Nonce);

        Assert.True(f.Consume(evidence, enrollment, pin, challenge.Nonce, out string candidate));
        Assert.Equal(f.Successor.Did, candidate);
        Assert.False(f.Consume(evidence, enrollment, pin, challenge.Nonce, out string replay));
        Assert.Equal(string.Empty, replay);
    }

    [Fact]
    public void LegacyUnboundChallengeCannotSatisfyAnExactEnrolledPolicy()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();
        var challenge = IssuerGuardianRecoveryChallenges.Issue(
            f.Store, f.TenantId, f.Previous.Did, Audience);
        string evidence = f.Proof(challenge.Nonce);

        Assert.False(f.Consume(evidence, enrollment, pin, challenge.Nonce, out string rejected));
        Assert.Equal(string.Empty, rejected);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));

        // The existing legacy SDK contract is still supported for callers
        // who explicitly choose verifier-provided guardian pins.
        Assert.True(IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
            f.Store, f.TenantId, evidence, f.Previous.Did,
            [f.GuardianOne.Did, f.GuardianTwo.Did], 2,
            Audience, challenge.Nonce, f.Clock, out string legacyCandidate));
        Assert.Equal(f.Successor.Did, legacyCandidate);
    }

    [Fact]
    public void GuardianOnlyBoundChallengeCannotMasqueradeAsExactEnrollment()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();
        var challenge = IssuerGuardianRecoveryChallenges.IssueBoundToGuardians(
            f.Store, f.TenantId, f.Previous.Did,
            [f.GuardianOne.Did, f.GuardianTwo.Did], 2, Audience);
        string evidence = f.Proof(challenge.Nonce);

        Assert.False(f.Consume(evidence, enrollment, pin, challenge.Nonce, out string rejected));
        Assert.Equal(string.Empty, rejected);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));

        Assert.True(IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
            f.Store, f.TenantId, evidence, f.Previous.Did,
            [f.GuardianOne.Did, f.GuardianTwo.Did], 2,
            Audience, challenge.Nonce, f.Clock, out string boundCandidate));
        Assert.Equal(f.Successor.Did, boundCandidate);
    }

    [Fact]
    public void ChallengeCannotSwitchBetweenValidEnrollmentFingerprintsWithSameGuardians()
    {
        var f = new Fixture();
        var (original, originalPin) = f.Enrollment();
        var challenge = f.Issue(original, originalPin);
        string replacement = IssuerGuardianRecoveryEnrollment.Create(
            f.Previous.Did, f.Previous.Seed,
            [f.GuardianOne.Did, f.GuardianTwo.Did], 2, Audience,
            Now.AddMinutes(-1), Now.AddMinutes(15));
        string replacementPin = IssuerGuardianRecoveryEnrollment.Fingerprint(replacement);
        string evidence = f.Proof(challenge.Nonce);

        Assert.NotEqual(originalPin, replacementPin);
        Assert.True(IssuerGuardianRecoveryEnrollment.TryVerify(
            replacement, f.Previous.Did, replacementPin, Audience,
            Now, out _, out _));
        Assert.False(f.Consume(evidence, replacement, replacementPin,
            challenge.Nonce, out string rejected));
        Assert.Equal(string.Empty, rejected);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));
        Assert.True(f.Consume(evidence, original, originalPin,
            challenge.Nonce, out string accepted));
        Assert.Equal(f.Successor.Did, accepted);
    }

    [Fact]
    public void ExactEnrollmentChallengeRetainsPurposeBoundCancellation()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();
        var challenge = f.Issue(enrollment, pin);

        Assert.True(IssuerGuardianRecoveryChallenges.TryCancel(
            f.Store, f.TenantId, f.Previous.Did,
            Audience, challenge.Nonce));
        Assert.False(f.Consume(f.Proof(challenge.Nonce), enrollment,
            pin, challenge.Nonce, out string candidate));
        Assert.Equal(string.Empty, candidate);
    }

    [Fact]
    public void OldIssuerCannotSubstituteAnUnpinnedNewGuardianRoster()
    {
        var f = new Fixture();
        var (original, pin) = f.Enrollment();
        var extra = NewKey();
        string replacement = IssuerGuardianRecoveryEnrollment.Create(
            f.Previous.Did, f.Previous.Seed, [f.GuardianOne.Did, extra.Did],
            2, Audience, Now.AddMinutes(-1), Now.AddMinutes(30));

        Assert.NotEqual(pin, IssuerGuardianRecoveryEnrollment.Fingerprint(replacement));
        Assert.Throws<ArgumentException>(() => f.Issue(replacement, pin));
        Assert.False(IssuerGuardianRecoveryEnrollment.TryVerify(replacement,
            f.Previous.Did, pin, Audience, Now, out string[] rejected, out int threshold));
        Assert.Empty(rejected);
        Assert.Equal(0, threshold);
        Assert.True(IssuerGuardianRecoveryEnrollment.TryVerify(original,
            f.Previous.Did, pin, Audience, Now, out string[] approved, out int quorum));
        Assert.Equal(2, approved.Length);
        Assert.Equal(2, quorum);
    }

    [Fact]
    public void WrongVerifierOldIssuerAndUnpinnedFingerprintCannotIssue()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();

        Assert.Throws<ArgumentException>(() => IssuerGuardianRecoveryEnrollment.IssueChallenge(
            f.Store, f.TenantId, enrollment, pin, f.Previous.Did,
            new Uri("https://another.example/recovery"), f.Clock));
        Assert.Throws<ArgumentException>(() => IssuerGuardianRecoveryEnrollment.IssueChallenge(
            f.Store, f.TenantId, enrollment, pin, NewKey().Did, Audience, f.Clock));
        Assert.Throws<ArgumentException>(() => f.Issue(enrollment, new string('0', 64)));
        Assert.True(IssuerGuardianRecoveryEnrollment.TryVerify(enrollment,
            f.Previous.Did, pin, Audience, Now, out _, out _));
    }

    [Fact]
    public void ForgedIssuerSignatureAndMalformedRosterFailClosed()
    {
        var f = new Fixture();
        var attacker = NewKey();
        Assert.Throws<ArgumentException>(() =>
            IssuerGuardianRecoveryEnrollment.Create(f.Previous.Did, attacker.Seed,
                [f.GuardianOne.Did, f.GuardianTwo.Did], 2, Audience,
                Now.AddMinutes(-1), Now.AddMinutes(30)));
        Assert.Throws<ArgumentException>(() =>
            IssuerGuardianRecoveryEnrollment.Create(f.Previous.Did, f.Previous.Seed,
                [f.GuardianOne.Did, f.GuardianOne.Did], 2, Audience,
                Now.AddMinutes(-1), Now.AddMinutes(30)));
        Assert.Throws<ArgumentException>(() =>
            IssuerGuardianRecoveryEnrollment.Create(f.Previous.Did, f.Previous.Seed,
                [f.Previous.Did, f.GuardianTwo.Did], 2, Audience,
                Now.AddMinutes(-1), Now.AddMinutes(30)));
    }

    [Fact]
    public void ExpiredOrNotYetEffectiveEnrollmentCannotAuthorizeRecovery()
    {
        var f = new Fixture();
        string expired = IssuerGuardianRecoveryEnrollment.Create(f.Previous.Did,
            f.Previous.Seed, [f.GuardianOne.Did, f.GuardianTwo.Did], 2,
            Audience, Now.AddMinutes(-4), Now.AddMinutes(-1));
        string future = IssuerGuardianRecoveryEnrollment.Create(f.Previous.Did,
            f.Previous.Seed, [f.GuardianOne.Did, f.GuardianTwo.Did], 2,
            Audience, Now.AddMinutes(1), Now.AddMinutes(30));

        Assert.Throws<ArgumentException>(() =>
            f.Issue(expired, IssuerGuardianRecoveryEnrollment.Fingerprint(expired)));
        Assert.Throws<ArgumentException>(() =>
            f.Issue(future, IssuerGuardianRecoveryEnrollment.Fingerprint(future)));
    }

    [Fact]
    public void InvalidProofDoesNotBurnPinnedEnrollmentChallenge()
    {
        var f = new Fixture();
        var (enrollment, pin) = f.Enrollment();
        var challenge = f.Issue(enrollment, pin);
        var rogue = NewKey();
        string invalid = IssuerGuardianRecovery.Create(f.Previous.Did,
            f.Successor.Did, f.Successor.Seed,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [f.GuardianOne.Did] = f.GuardianOne.Seed,
                [rogue.Did] = rogue.Seed
            }, Audience, challenge.Nonce, f.Clock);

        Assert.False(f.Consume(invalid, enrollment, pin, challenge.Nonce, out string rejected));
        Assert.Equal(string.Empty, rejected);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));
        Assert.True(f.Consume(f.Proof(challenge.Nonce), enrollment, pin,
            challenge.Nonce, out string accepted));
        Assert.Equal(f.Successor.Did, accepted);
    }

    [Fact]
    public void EnrollmentExpiryAfterIssuingChallengeBlocksRedemption()
    {
        var f = new Fixture();
        string enrollment = IssuerGuardianRecoveryEnrollment.Create(
            f.Previous.Did, f.Previous.Seed, [f.GuardianOne.Did, f.GuardianTwo.Did],
            2, Audience, Now.AddMinutes(-5), Now.AddSeconds(5));
        string pin = IssuerGuardianRecoveryEnrollment.Fingerprint(enrollment);
        var challenge = f.Issue(enrollment, pin);
        string evidence = f.Proof(challenge.Nonce);
        f.Clock.Advance(TimeSpan.FromSeconds(6));

        Assert.False(f.Consume(evidence, enrollment, pin, challenge.Nonce, out string candidate));
        Assert.Equal(string.Empty, candidate);
        Assert.NotNull(f.Store.Find(f.TenantId, Audience.AbsoluteUri, challenge.Nonce));
    }

    private sealed class Fixture
    {
        public Guid TenantId { get; } = Guid.NewGuid();
        public FixedClock Clock { get; } = new(Now);
        public (string Did, byte[] Seed) Previous { get; } = NewKey();
        public (string Did, byte[] Seed) Successor { get; } = NewKey();
        public (string Did, byte[] Seed) GuardianOne { get; } = NewKey();
        public (string Did, byte[] Seed) GuardianTwo { get; } = NewKey();
        public InMemoryPresentationChallengeStore Store { get; }

        public Fixture() => Store = new InMemoryPresentationChallengeStore(Clock);

        public (string Jwt, string Fingerprint) Enrollment()
        {
            string jwt = IssuerGuardianRecoveryEnrollment.Create(
                Previous.Did, Previous.Seed, [GuardianOne.Did, GuardianTwo.Did],
                2, Audience, Now.AddMinutes(-1), Now.AddMinutes(30));
            return (jwt, IssuerGuardianRecoveryEnrollment.Fingerprint(jwt));
        }

        public PresentationChallenge Issue(string enrollment, string pin) =>
            IssuerGuardianRecoveryEnrollment.IssueChallenge(Store, TenantId,
                enrollment, pin, Previous.Did, Audience, Clock);

        public string Proof(string nonce) => IssuerGuardianRecovery.Create(
            Previous.Did, Successor.Did, Successor.Seed,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [GuardianOne.Did] = GuardianOne.Seed,
                [GuardianTwo.Did] = GuardianTwo.Seed
            }, Audience, nonce, Clock);

        public bool Consume(string proof, string enrollment, string pin,
            string nonce, out string candidate) =>
            IssuerGuardianRecoveryEnrollment.TryVerifyAndConsume(
                Store, TenantId, proof, enrollment, pin, Previous.Did,
                Audience, nonce, Clock, out candidate);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
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
