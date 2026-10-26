using System;
using System.Threading.Tasks;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace HeroSSID.Integration.Tests;

public sealed class PresentationChallengeCapacityRegressionTests(DatabaseFixture fixture) : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture = fixture;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefaultTenantAllowanceLeavesGlobalCapacityForAnotherTenant(bool postgres)
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        IPresentationChallengeStore store = postgres
            ? new PostgresPresentationChallengeStore(source, TimeProvider.System, capacity: 256)
            : new InMemoryPresentationChallengeStore(TimeProvider.System, capacity: 256);
        var tenant = Guid.NewGuid();
        for (var i = 0; i < 128; i++)
        {
            Assert.NotNull(store.Issue(tenant, "audience", "issuer"));
        }

        Assert.Throws<InvalidOperationException>(() => store.Issue(tenant, "audience", "issuer"));
        Assert.NotNull(store.Issue(Guid.NewGuid(), "audience", "issuer"));
    }

    [Fact]
    public async Task NonceAndAudienceStorageMatchOrdinalQueryCollation()
    {
        await PrepareAsync().ConfigureAwait(true);
        await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
        await using var connection = await source.OpenConnectionAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await using var command = new NpgsqlCommand(
            """
            SELECT count(*) FROM pg_attribute a
            JOIN pg_collation c ON c.oid = a.attcollation
            WHERE a.attrelid = 'presentation_challenges'::regclass
                AND a.attname IN ('nonce', 'audience') AND c.collname = 'C'
            """, connection);
        Assert.Equal(2L, await command.ExecuteScalarAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
    }

    private async Task PrepareAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await db.Database.ExecuteSqlRawAsync("DELETE FROM presentation_challenges", TestContext.Current.CancellationToken).ConfigureAwait(true);
    }
}
