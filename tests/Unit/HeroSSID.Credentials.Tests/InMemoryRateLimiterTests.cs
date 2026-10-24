using HeroSSID.Infrastructure.RateLimiting;
using Xunit;

namespace HeroSSID.Credentials.Tests;

public sealed class InMemoryRateLimiterTests
{
    [Fact]
    public async Task ConcurrentReservationsNeverOversubscribeOneTenantOperation()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 7);
        var tenant = Guid.NewGuid();
        var granted = 0;

        Parallel.For(0, 256, _ =>
        {
            if (limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").GetAwaiter().GetResult())
            {
                Interlocked.Increment(ref granted);
            }
        });

        Assert.Equal(7, granted);
        Assert.False(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.False(await limiter.IsAllowedAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
    }

    [Fact]
    public async Task RejectedReservationsDoNotChargeOtherWindowsAndExpiredPermitsReturn()
    {
        var clock = new ManualTimeProvider();
        using var limiter = new InMemoryRateLimiter(TimeSpan.FromSeconds(10), 2, clock);
        var tenant = Guid.NewGuid();
        var anotherTenant = Guid.NewGuid();

        Assert.True(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.False(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_ISSUE").ConfigureAwait(true));
        Assert.True(await limiter.TryAcquireAsync(anotherTenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.False(await limiter.IsAllowedAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));

        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.True(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.IsAllowedAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.False(await limiter.TryAcquireAsync(tenant, "CREDENTIAL_VERIFY").ConfigureAwait(true));
    }

    [Fact]
    public async Task ObservationDoesNotReserveButLegacyRecordingRemainsVisible()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var tenant = Guid.NewGuid();

        Assert.True(await limiter.IsAllowedAsync(tenant, "DID_SIGN").ConfigureAwait(true));
        Assert.True(await limiter.IsAllowedAsync(tenant, "DID_SIGN").ConfigureAwait(true));
        await limiter.RecordOperationAsync(tenant, "DID_SIGN").ConfigureAwait(true);
        Assert.False(await limiter.TryAcquireAsync(tenant, "DID_SIGN").ConfigureAwait(true));
    }

    [Fact]
    public async Task CancelledReservationCannotConsumeCapacity()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var tenant = Guid.NewGuid();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            limiter.TryAcquireAsync(tenant, "DID_CREATE", cancellation.Token)).ConfigureAwait(true);
        Assert.True(await limiter.TryAcquireAsync(tenant, "DID_CREATE").ConfigureAwait(true));
    }

    [Fact]
    public void RejectsNonPositiveWindowAndCapacity()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryRateLimiter(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryRateLimiter(TimeSpan.FromSeconds(1), 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryRateLimiter(TimeSpan.FromSeconds(1), -1));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 25, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
