using System;
using System.Threading;
using System.Threading.Tasks;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace HeroSSID.Integration.Tests;

/// <summary>Real database lock waits with an independently advanced clock, not timing guesses.</summary>
public sealed class PresentationChallengeReviewRegressionTests(DatabaseFixture fixture) : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture = fixture;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IssuanceSamplesTimeAfterAdmissionLock(bool fillCapacityBeforeWait)
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var application = "challenge-issue-" + Guid.NewGuid().ToString("N");
        await using var workerSource = CreateWorkerSource(application);
        var clock = new ReviewClock();
        var tenant = Guid.NewGuid();
        var store = new PostgresPresentationChallengeStore(workerSource, clock, capacity: 1);
        if (fillCapacityBeforeWait)
        {
            store.Issue(tenant, "audience", "issuer", TimeSpan.FromSeconds(1));
        }

        await using var blocker = await source.OpenConnectionAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await using var transaction = await blocker.BeginTransactionAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await using (var command = new NpgsqlCommand("SELECT pg_advisory_xact_lock(1213416281, 1128475468)", blocker, transaction))
        {
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        var issuance = Task.Run(() => store.Issue(tenant, "audience", "issuer", TimeSpan.FromSeconds(1)), TestContext.Current.CancellationToken);
        try
        {
            await WaitForLockAsync(source, application).ConfigureAwait(true);
            clock.Advance(TimeSpan.FromSeconds(2));
        }
        finally
        {
            await transaction.RollbackAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        var challenge = await issuance.ConfigureAwait(true);
        Assert.Equal(clock.GetUtcNow().AddSeconds(1), challenge.ExpiresAt);
        Assert.NotNull(store.Find(tenant, challenge.Audience, challenge.Nonce));
    }

    [Fact]
    public async Task ConsumptionRejectsChallengeThatExpiresWhileWaitingForItsRowLock()
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var application = "challenge-consume-" + Guid.NewGuid().ToString("N");
        await using var workerSource = CreateWorkerSource(application);
        var clock = new ReviewClock();
        var tenant = Guid.NewGuid();
        var store = new PostgresPresentationChallengeStore(workerSource, clock);
        var challenge = store.Issue(tenant, "audience", "issuer", TimeSpan.FromSeconds(1));
        await using var blocker = await source.OpenConnectionAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await using var transaction = await blocker.BeginTransactionAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await using (var command = new NpgsqlCommand("SELECT nonce FROM presentation_challenges WHERE nonce = @nonce FOR UPDATE", blocker, transaction))
        {
            command.Parameters.AddWithValue("nonce", challenge.Nonce);
            await command.ExecuteScalarAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        var consumption = Task.Run(() => store.TryConsume(tenant, challenge.Audience, challenge.Nonce), TestContext.Current.CancellationToken);
        try
        {
            await WaitForLockAsync(source, application).ConfigureAwait(true);
            clock.Advance(TimeSpan.FromSeconds(2));
        }
        finally
        {
            await transaction.RollbackAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }

        Assert.False(await consumption.ConfigureAwait(true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OneSecondChallengeRetainsFractionalSecondLifetime(bool postgres)
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var clock = new ReviewClock();
        clock.Advance(TimeSpan.FromMilliseconds(999));
        IPresentationChallengeStore store = postgres
            ? new PostgresPresentationChallengeStore(source, clock)
            : new InMemoryPresentationChallengeStore(clock);
        var tenant = Guid.NewGuid();
        var issuedAt = clock.GetUtcNow();
        var challenge = store.Issue(tenant, "audience", "issuer", TimeSpan.FromSeconds(1));
        Assert.Equal(TimeSpan.FromSeconds(1), challenge.ExpiresAt - issuedAt);
        clock.Advance(TimeSpan.FromMilliseconds(500));
        Assert.NotNull(store.Find(tenant, challenge.Audience, challenge.Nonce));
        clock.Advance(TimeSpan.FromMilliseconds(500));
        Assert.False(store.TryConsume(tenant, challenge.Audience, challenge.Nonce));
    }

    [Fact]
    public async Task ConsumedRecordsStillCountTowardsRetainedStorageCapacity()
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var store = new PostgresPresentationChallengeStore(source, new ReviewClock(), capacity: 1);
        var tenant = Guid.NewGuid();
        var challenge = store.Issue(tenant, "audience", "issuer");
        Assert.True(store.TryConsume(tenant, challenge.Audience, challenge.Nonce));
        Assert.Throws<InvalidOperationException>(() => store.Issue(tenant, "audience", "issuer"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OversizedLookupAudienceIsRejectedWithoutOpeningDatabase(bool consume)
    {
        using var source = NpgsqlDataSource.Create("Host=127.0.0.1;Port=1;Username=unused;Database=unused;Timeout=1;Pooling=false");
        var store = new PostgresPresentationChallengeStore(source, new ReviewClock());
        var audience = new string('a', 2049);
        var nonce = new string('A', 43);
        if (consume)
        {
            Assert.False(store.TryConsume(Guid.NewGuid(), audience, nonce));
        }
        else
        {
            Assert.Null(store.Find(Guid.NewGuid(), audience, nonce));
        }
    }

    private NpgsqlDataSource CreateWorkerSource(string application) => NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(_fixture.ConnectionString) { ApplicationName = application }.ConnectionString);

    private static async Task WaitForLockAsync(NpgsqlDataSource source, string application)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await using var connection = await source.OpenConnectionAsync(timeout.Token).ConfigureAwait(true);
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = @application AND wait_event_type = 'Lock')", connection);
        command.Parameters.AddWithValue("application", application);
        while (!Equals(await command.ExecuteScalarAsync(timeout.Token).ConfigureAwait(true), true))
        {
            await Task.Delay(10, timeout.Token).ConfigureAwait(true);
        }
    }

    private async Task PrepareAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await db.Database.ExecuteSqlRawAsync("DELETE FROM presentation_challenges", TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private sealed class ReviewClock : TimeProvider
    {
        private long _ticks = new DateTimeOffset(2035, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
        public void Advance(TimeSpan delta) => Interlocked.Add(ref _ticks, delta.Ticks);
    }
}
