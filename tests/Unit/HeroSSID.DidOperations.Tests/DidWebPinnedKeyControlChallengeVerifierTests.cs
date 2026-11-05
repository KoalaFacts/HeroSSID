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
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());

        Assert.Equal(32, challenge.GetNonce().Length);
        Assert.Equal(InitialTime, challenge.IssuedAt);
        Assert.Equal(InitialTime.AddMinutes(2), challenge.ExpiresAt);
        Assert.True(verifier.TryVerifyAndConsume(challenge.GetNonce(), signature));
        Assert.False(verifier.TryVerifyAndConsume(challenge.GetNonce(), signature));
    }

    [Fact]
    public void WrongSignerAndTamperingDoNotConsumeTheGenuineChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        using Key attacker = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        byte[] forged = SignatureAlgorithm.Ed25519.Sign(attacker, challenge.GetSigningInput());
        byte[] changedNonce = challenge.GetNonce();
        changedNonce[0] ^= 1;
        byte[] changedSignature = (byte[])genuine.Clone();
        changedSignature[0] ^= 1;

        Assert.False(verifier.TryVerifyAndConsume(challenge.GetNonce(), forged));
        Assert.False(verifier.TryVerifyAndConsume(changedNonce, genuine));
        Assert.False(verifier.TryVerifyAndConsume(challenge.GetNonce(), changedSignature));
        Assert.False(verifier.TryVerifyAndConsume(new byte[31], genuine));
        Assert.True(verifier.TryVerifyAndConsume(challenge.GetNonce(), genuine));
    }

    [Fact]
    public void ExpiredChallengesFailAndReleaseBoundedCapacity()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock, capacity: 1);
        DidWebPinnedKeyControlChallenge first = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, first.GetSigningInput());
        Assert.Throws<InvalidOperationException>(() => verifier.Issue());

        clock.Current = first.ExpiresAt;
        Assert.False(verifier.TryVerifyAndConsume(first.GetNonce(), signature));
        DidWebPinnedKeyControlChallenge second = verifier.Issue();
        Assert.NotEqual(Convert.ToHexString(first.GetNonce()), Convert.ToHexString(second.GetNonce()));
        Assert.True(verifier.TryVerifyAndConsume(second.GetNonce(),
            SignatureAlgorithm.Ed25519.Sign(signer, second.GetSigningInput())));
    }

    [Fact]
    public void MutatingExposedBuffersCannotAlterTheStoredChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());
        byte[] exposedNonce = challenge.GetNonce();
        byte[] exposedInput = challenge.GetSigningInput();
        exposedNonce[0] ^= 1;
        exposedInput[0] ^= 1;

        Assert.False(verifier.TryVerifyAndConsume(exposedNonce, genuine));
        Assert.True(verifier.TryVerifyAndConsume(challenge.GetNonce(), genuine));
    }

    [Fact]
    public async Task ConcurrentDuplicateSubmissionsYieldExactlyOneSuccessAsync()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var verifier = NewVerifier(signer, new ManualClock());
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());

        Task<bool>[] attempts = Enumerable.Range(0, 24)
            .Select(_ => Task.Run(() => verifier.TryVerifyAndConsume(challenge.GetNonce(), signature)))
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
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());

        Assert.False(independentVerifier.TryVerifyAndConsume(challenge.GetNonce(), signature));
        Assert.True(verifier.TryVerifyAndConsume(challenge.GetNonce(), signature));
    }


    [Fact]
    public async Task CallerMutatingNonceWhileVerifyHoldsGateCannotConsumeAnotherChallengeAsync()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock);
        DidWebPinnedKeyControlChallenge first = verifier.Issue();
        DidWebPinnedKeyControlChallenge second = verifier.Issue();
        byte[] firstSignature = SignatureAlgorithm.Ed25519.Sign(signer, first.GetSigningInput());
        byte[] secondSignature = SignatureAlgorithm.Ed25519.Sign(signer, second.GetSigningInput());
        byte[] mutableFirstNonce = first.GetNonce();
        using var entered = new ManualResetEventSlim(false);
        using var resume = new ManualResetEventSlim(false);

        // The verifier has already selected the first nonce but has not yet
        // rebuilt its signed bytes. Hold its lock at the clock read.
        clock.BeforeRead = () =>
        {
            entered.Set();
            if (!resume.Wait(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken))
            {
                throw new TimeoutException("Timed out resuming verifier clock read.");
            }
        };

        Task<bool> substituted = Task.Run(
            () => verifier.TryVerifyAndConsume(mutableFirstNonce, secondSignature));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            byte[] secondNonce = second.GetNonce();
            Buffer.BlockCopy(secondNonce, 0, mutableFirstNonce, 0, secondNonce.Length);
        }
        finally
        {
            resume.Set();
        }

        Assert.False(await substituted.ConfigureAwait(false));
        clock.BeforeRead = null;
        Assert.True(verifier.TryVerifyAndConsume(first.GetNonce(), firstSignature));
        Assert.True(verifier.TryVerifyAndConsume(second.GetNonce(), secondSignature));
    }

    [Fact]
    public void UtcRollbackCannotExtendAnExpiredMonotonicChallenge()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock, capacity: 1);
        DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
        byte[] genuine = SignatureAlgorithm.Ed25519.Sign(signer, challenge.GetSigningInput());

        // UTC still appears within the window after a backward correction,
        // while the verifier's elapsed monotonic time exceeds the TTL.
        clock.Current = InitialTime.AddSeconds(10);
        clock.MonotonicTicks = TimeSpan.FromMinutes(3).Ticks;
        Assert.False(verifier.TryVerifyAndConsume(challenge.GetNonce(), genuine));
    }

    [Fact]
    public void ExpiredMonotonicChallengeReleasesCapacityAfterUtcRollback()
    {
        using Key signer = Key.Create(SignatureAlgorithm.Ed25519);
        var clock = new ManualClock();
        var verifier = NewVerifier(signer, clock, capacity: 1);
        DidWebPinnedKeyControlChallenge previous = verifier.Issue();
        clock.Current = InitialTime.AddSeconds(10);
        clock.MonotonicTicks = TimeSpan.FromMinutes(3).Ticks;

        DidWebPinnedKeyControlChallenge replacement = verifier.Issue();
        Assert.NotEqual(Convert.ToHexString(previous.GetNonce()),
            Convert.ToHexString(replacement.GetNonce()));
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

        public long MonotonicTicks { get; set; }

        public Action? BeforeRead { get; set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => MonotonicTicks;

        public override DateTimeOffset GetUtcNow()
        {
            BeforeRead?.Invoke();
            return Current;
        }
    }
}
