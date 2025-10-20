using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;

namespace HeroSSID.Integration.Tests.TestInfrastructure;

/// <summary>
/// Database fixture for integration tests using Testcontainers
/// Provides a disposable PostgreSQL container for isolated test execution
/// </summary>
public sealed class DatabaseFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _postgresContainer;

    public string ConnectionString { get; private set; } = string.Empty;

    /// <summary>
    /// Initializes the PostgreSQL container before tests run
    /// </summary>
    public async ValueTask InitializeAsync()
    {
        _postgresContainer = new PostgreSqlBuilder()
            .WithImage("postgres:17")
            .WithDatabase("herossid_test")
            .WithUsername("herossid_test")
            .WithPassword("test_password")
            .WithCleanUp(true)
            .Build();

        await _postgresContainer.StartAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);

        ConnectionString = _postgresContainer.GetConnectionString();
    }

    /// <summary>
    /// Creates a new DbContext instance for testing
    /// </summary>
    /// <typeparam name="TContext">The DbContext type to create</typeparam>
    /// <returns>A configured DbContext instance</returns>
    public TContext CreateDbContext<TContext>() where TContext : DbContext
    {
        var options = new DbContextOptionsBuilder<TContext>()
            .UseNpgsql(ConnectionString)
            .Options;

        return (TContext)Activator.CreateInstance(typeof(TContext), options)!;
    }

    /// <summary>
    /// Disposes the PostgreSQL container after tests complete
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_postgresContainer != null)
        {
            await _postgresContainer.DisposeAsync().ConfigureAwait(false);
        }
    }
}
