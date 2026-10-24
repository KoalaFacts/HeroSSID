using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using HeroSSID.Credentials.VerifiablePresentations;
using Xunit;

namespace HeroSSID.Credentials.Tests;

public sealed class PresentationChallengeStoreTests
{
    [Fact]
    public void CapacityRejectsWithoutEvictingLiveRequestsAndExpiredEntriesAreReclaimed()
    {
        var clock = new TestTimeProvider();
        var store = new InMemoryPresentationChallengeStore(clock, capacity: 1);
        var tenant = Guid.NewGuid();
        var challenge = store.Issue(tenant, "verifier", "issuer", TimeSpan.FromSeconds(10));
        Assert.Throws<InvalidOperationException>(() => store.Issue(tenant, "verifier", "issuer"));
        Assert.NotNull(store.Find(tenant, "verifier", challenge.Nonce));
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.False(store.TryConsume(tenant, "verifier", challenge.Nonce));
        Assert.NotEqual(challenge.Nonce, store.Issue(tenant, "verifier", "issuer").Nonce);
    }

    [Fact]
    public void InvalidAttemptsDoNotConsumeAndAtomicConsumptionAcceptsExactlyOnce()
    {
        var store = new InMemoryPresentationChallengeStore(TimeProvider.System);
        var tenant = Guid.NewGuid();
        var challenge = store.Issue(tenant, "verifier", "issuer");
        Assert.False(store.TryConsume(Guid.NewGuid(), "verifier", challenge.Nonce));
        Assert.False(store.TryConsume(tenant, "other", challenge.Nonce));
        var successes = 0;
        Parallel.For(0, 32, _ =>
        {
            if (store.TryConsume(tenant, "verifier", challenge.Nonce))
            {
                Interlocked.Increment(ref successes);
            }
        });
        Assert.Equal(1, successes);
        Assert.Null(store.Find(tenant, "verifier", challenge.Nonce));
    }

    [Fact]
    public void ChallengeLifetimeAndIdentifiersAreBounded()
    {
        var store = new InMemoryPresentationChallengeStore(TimeProvider.System);
        var tenant = Guid.NewGuid();
        Assert.Throws<ArgumentException>(() => store.Issue(Guid.Empty, "verifier", "issuer"));
        Assert.Throws<ArgumentException>(() => store.Issue(tenant, "", "issuer"));
        Assert.Throws<ArgumentException>(() => store.Issue(tenant, "verifier", ""));
        Assert.Throws<ArgumentException>(() => store.Issue(tenant, new string('a', 2049), "issuer"));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Issue(tenant, "verifier", "issuer", TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Issue(tenant, "verifier", "issuer", TimeSpan.FromMinutes(6)));
        var nonces = Enumerable.Range(0, 64).Select(_ => store.Issue(tenant, "verifier", "issuer").Nonce).ToArray();
        Assert.All(nonces, nonce => Assert.Equal(43, nonce.Length));
        Assert.Equal(nonces.Length, nonces.Distinct(StringComparer.Ordinal).Count());
    }

    private sealed class TestTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
