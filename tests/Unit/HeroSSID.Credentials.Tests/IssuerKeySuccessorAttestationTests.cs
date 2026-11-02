using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerKeySuccessorAttestationTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Audience = new("https://verifier.example/issuer-successor");
    private const string Nonce = "challengeNonce_1234567890ABCDEF";

    [Fact]
    public void IndependentVerifierAcceptsBothRealIssuerSignaturesForPinnedPreviousDid()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        string proof = Create(oldKey, newKey);
        Assert.True(IssuerKeySuccessorAttestation.TryVerify(
            proof, oldKey.Did, Audience, Nonce, Now.AddSeconds(1), out string successor));
        Assert.Equal(newKey.Did, successor);
        Assert.NotEqual(oldKey.Did, successor);
    }

    [Fact]
    public void WrongSignerCannotClaimToOwnPreviousOrSuccessorDid()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var attacker = NewKey();
        Assert.Throws<ArgumentException>(() => IssuerKeySuccessorAttestation.Create(
            oldKey.Did, newKey.Did, attacker.Seed, newKey.Seed,
            Audience, Nonce, TimeProviderForNow()));
        Assert.Throws<ArgumentException>(() => IssuerKeySuccessorAttestation.Create(
            oldKey.Did, newKey.Did, oldKey.Seed, attacker.Seed,
            Audience, Nonce, TimeProviderForNow()));
    }

    [Fact]
    public void IndependentVerifierRejectsForeignAudienceNonceAndTrustedPreviousDid()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        string proof = Create(oldKey, newKey);
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            proof, oldKey.Did, new Uri("https://foreign.example/issuer-successor"),
            Nonce, Now, out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            proof, oldKey.Did, Audience, "different_nonce_1234567890",
            Now, out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            proof, newKey.Did, Audience, Nonce, Now, out _));
    }

    [Fact]
    public void ProofIsRejectedBeforeIssueTimeAndAfterFiveMinuteLifetime()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        string proof = Create(oldKey, newKey);
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            proof, oldKey.Did, Audience, Nonce, Now.AddSeconds(-1), out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            proof, oldKey.Did, Audience, Nonce, Now.AddMinutes(5), out _));
    }

    [Fact]
    public void CannotCombineValidSignaturesForDifferentStatements()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        string first = Create(oldKey, newKey);
        string second = IssuerKeySuccessorAttestation.Create(
            oldKey.Did, newKey.Did, oldKey.Seed, newKey.Seed,
            Audience, "other_nonce_1234567890ABCDE", TimeProviderForNow());

        using var firstDoc = JsonDocument.Parse(first);
        using var secondDoc = JsonDocument.Parse(second);
        string switched = JsonSerializer.Serialize(new
        {
            previousSignature = firstDoc.RootElement.GetProperty("previousSignature").GetString(),
            successorSignature = secondDoc.RootElement.GetProperty("successorSignature").GetString()
        });
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            switched, oldKey.Did, Audience, Nonce, Now, out string successor));
        Assert.Equal(string.Empty, successor);
    }

    [Fact]
    public void SameKeyOrMalformedProofCannotBecomeSuccessor()
    {
        var oldKey = NewKey();
        Assert.Throws<ArgumentException>(() => IssuerKeySuccessorAttestation.Create(
            oldKey.Did, oldKey.Did, oldKey.Seed, oldKey.Seed,
            Audience, Nonce, TimeProviderForNow()));
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            "{not-json", oldKey.Did, Audience, Nonce, Now, out _));
        Assert.False(IssuerKeySuccessorAttestation.TryVerify(
            "{\"previousSignature\":\"x\",\"successorSignature\":\"y\"}",
            oldKey.Did, Audience, Nonce, Now, out _));
    }

    [Fact]
    public void SuccessorAdmissionAtomicallyConsumesChallengeAndRejectsReplay()
    {
        var previous = NewKey();
        var successor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, previous.Did, challenges);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, challenge.Nonce, clock);

        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string admitted));
        Assert.Equal(successor.Did, admitted);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string replay));
        Assert.Equal(string.Empty, replay);
    }

    [Fact]
    public void SuccessorAdmissionRejectsWrongTenantAndPreviousIssuerWithoutSpendingNonce()
    {
        var previous = NewKey();
        var successor = NewKey();
        var impostor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, previous.Did, challenges);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, challenge.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            Guid.NewGuid(), challenges, clock, out string foreignTenant));
        Assert.Equal(string.Empty, foreignTenant);
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, impostor.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string foreignIssuer));
        Assert.Equal(string.Empty, foreignIssuer);
        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string admitted));
        Assert.Equal(successor.Did, admitted);
    }

    [Fact]
    public void InvalidSuccessorProofDoesNotSpendValidVerifierChallenge()
    {
        var previous = NewKey();
        var successor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, previous.Did, challenges);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, challenge.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof + "tampered", previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string forged));
        Assert.Equal(string.Empty, forged);
        Assert.True(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string admitted));
        Assert.Equal(successor.Did, admitted);
    }

    [Fact]
    public void ConcurrentSuccessorAdmissionAllowsExactlyOneVerifierDecision()
    {
        var previous = NewKey();
        var successor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, previous.Did, challenges);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, challenge.Nonce, clock);
        int accepted = 0;
        Parallel.For(0, 24, _ =>
        {
            if (IssuerKeySuccessorAttestation.TryVerifyAndConsume(
                proof, previous.Did, Audience, challenge.Nonce,
                tenant, challenges, clock, out string admitted))
            {
                Assert.Equal(successor.Did, admitted);
                Interlocked.Increment(ref accepted);
            }
        });

        Assert.Equal(1, accepted);
    }

    [Fact]
    public void PresentationChallengeCannotAuthorizeIssuerSuccessorAdmission()
    {
        var previous = NewKey();
        var successor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var presentation = challenges.Issue(tenant, Audience.AbsoluteUri, previous.Did);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, presentation.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, presentation.Nonce,
            tenant, challenges, clock, out string result));
        Assert.Equal(string.Empty, result);
        Assert.NotNull(challenges.Find(tenant, Audience.AbsoluteUri, presentation.Nonce));
    }

    [Fact]
    public void ExpiryDuringAtomicConsumptionNeverReleasesSuccessor()
    {
        var previous = NewKey();
        var successor = NewKey();
        var clock = TimeProviderForNow();
        var challenges = new ExpiringConsumptionStore(
            new InMemoryPresentationChallengeStore(clock), clock);
        var tenant = Guid.NewGuid();
        var challenge = IssuerKeySuccessorAttestation.IssueChallenge(
            tenant, Audience, previous.Did, challenges);
        string proof = IssuerKeySuccessorAttestation.Create(
            previous.Did, successor.Did, previous.Seed, successor.Seed,
            Audience, challenge.Nonce, clock);

        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out string result));
        Assert.Equal(string.Empty, result);
        Assert.False(IssuerKeySuccessorAttestation.TryVerifyAndConsume(
            proof, previous.Did, Audience, challenge.Nonce,
            tenant, challenges, clock, out _));
    }

    private sealed class ExpiringConsumptionStore(
        IPresentationChallengeStore inner, FixedClock clock) : IPresentationChallengeStore
    {
        public PresentationChallenge Issue(Guid tenant, string audience, string issuer,
            TimeSpan? lifetime = null) => inner.Issue(tenant, audience, issuer, lifetime);

        public PresentationChallenge? Find(Guid tenant, string audience, string nonce) =>
            inner.Find(tenant, audience, nonce);

        public bool TryConsume(Guid tenant, string audience, string nonce)
        {
            bool accepted = inner.TryConsume(tenant, audience, nonce);
            if (accepted)
            {
                clock.Advance(TimeSpan.FromMinutes(6));
            }

            return accepted;
        }
    }

    private static string Create((string Did, byte[] Seed) oldKey, (string Did, byte[] Seed) newKey) =>
        IssuerKeySuccessorAttestation.Create(
            oldKey.Did, newKey.Did, oldKey.Seed, newKey.Seed,
            Audience, Nonce, TimeProviderForNow());

    private static FixedClock TimeProviderForNow() => new FixedClock(Now);

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var didBytes = new byte[34];
        didBytes[0] = 0xed;
        didBytes[1] = 0x01;
        publicKey.CopyTo(didBytes, 2);
        return ("did:key:z" + SimpleBase.Base58.Bitcoin.Encode(didBytes),
            key.Export(KeyBlobFormat.RawPrivateKey));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan elapsed) => _now = _now.Add(elapsed);
    }
}
