using System.Security.Cryptography;
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class DidWebPinnedKeyControlChallengeVerifierTests
{
    private const string Did = "did:web:issuer.example.org";
    private const string Fragment = "#key-2";
    private static readonly Uri Audience = new("https://verifier.example.org/prove-key");
    private static readonly DateTimeOffset InitialTime = new(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ARealIndependentSignerCanCompleteOnlyOnce()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.SigningInput);

        Assert.Equal(32, challenge.Nonce.Length);
        Assert.Equal(InitialTime, challenge.IssuedAt);
        Assert.Equal(InitialTime.AddMinutes(2), challenge.ExpiresAt);
        Assert.True(verifier.TryVerifyAndConsume(challenge.Nonce, signature));
        Assert.False(verifier.TryVerifyAndConsume(challenge.Nonce, signature));
    }

    [Fact]
    public void WrongSignerAndTamperingDoNotConsumeTheGenuineChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.SigningInput);
        byte[] forged = SignatureAlgorithm.Ed25519.Sign(attacker, challenge.SigningInput);
        byte[] changedNonce = challenge.Nonce;
        changedNonce[0] ^= 1;
        byte[] changedSignature = (byte[])genuine.Clone();
        changedSignature[0] ^= 1;

        Assert.False(verifier.TryVerifyAndConsume(challenge.Nonce, forged));
        Assert.False(verifier.TryVerifyAndConsume(changedNonce, genuine));
        Assert.False(verifier.TryVerifyAndConsume(challenge.Nonce, changedSignature));
        Assert.False(verifier.TryVerifyAndConsume(new byte[31], genuine));
        Assert.True(verifier.TryVerifyAndConsume(challenge.Nonce, genuine));
    }

    [Fact]
    public void ExpiredChallengesFailAndReleaseBoundedCapacity()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock, capacity: 1);
        DidWebPinnedKeyControlChallenge first = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, first.SigningInput);
        Assert.Throws<InvalidOperationException>(() => verifier.Issue());

        clock.Current = first.ExpiresAt;
        Assert.False(verifier.TryVerifyAndConsume(first.Nonce, signature));
        DidWebPinnedKeyControlChallenge second = verifier.Issue();
        Assert.NotEqual(Convert.ToHexString(first.Nonce), Convert.ToHexString(second.Nonce));
        Assert.True(verifier.TryVerifyAndConsume(second.Nonce,
            SignatureAlgorithm.Ed25519.Sign(signer, second.SigningInput)));
    }

    [Fact]
    public void MutatingExposedBuffersCannotAlterTheStoredChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.SigningInput);
        byte[] exposedNonce = challenge.Nonce;
        byte[] exposedInput = challenge.SigningInput;
        exposedNonce[0] ^= 1;
        exposedInput[0] ^= 1;

        Assert.False(verifier.TryVerifyAndConsume(exposedNonce, genuine));
        Assert.True(verifier.TryVerifyAndConsume(challenge.Nonce, genuine));
    }

    [Fact]
    public async Task ConcurrentDuplicateSubmissionsYieldExactlyOneSuccess()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.SigningInput);

        Task<bool>[] attempts = Enumerable.Range(0, 24)
            .Select(_ => Task.Run(() => verifier.TryVerifyAndConsume(challenge.Nonce, signature)))
            .ToArray();
        bool[] results = await Task.WhenAll(attempts);
        Assert.Equal(1, results.Count(static accepted => accepted));
    }

    [Fact]
    public void IsolatedVerifierInstanceCannotReplayAnOthersChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock);
        var independentVerifier = NewVerifier(signer, clock);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.SigningInput);

        Assert.False(independentVerifier.TryVerifyAndConsume(challenge.Nonce, signature));
        Assert.True(verifier.TryVerifyAndConsume(challenge.Nonce, signature));
    }

    [Fact]
    public void RejectsInvalidVerifierConfigurationBeforeIssuing()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] pin = signer.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var clock = new ManualClock();
        Assert.Throws<ArgumentException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            "did:key:not-web", Fragment, Audience, pin, clock));
        Assert.Throws<ArgumentException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            Did, "#other", Audience, pin, clock));
        Assert.Throws<ArgumentException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            Did, Fragment, new Uri("http://verifier.example.org/prove-key"), pin, clock));
        Assert.Throws<ArgumentException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            Did, Fragment, Audience, new byte[31], clock));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            Did, Fragment, Audience, pin, clock, capacity: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DidWebPinnedKeyControlChallengeVerifier(
            Did, Fragment, Audience, pin, clock, lifetime: TimeSpan.FromMinutes(6)));
    }

    private static DidWebPinnedKeyControlChallengeVerifier NewVerifier(
        Key signer, ManualClock clock, int capacity = 32) =>
        new(Did, Fragment, Audience, signer.PublicKey.Export(KeyBlobFormat.RawPublicKey),
            clock, capacity, TimeSpan.FromMinutes(2));

    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Current { get; set; } = InitialTime;

        public override DateTimeOffset GetUtcNow() => Current;
    }
}
