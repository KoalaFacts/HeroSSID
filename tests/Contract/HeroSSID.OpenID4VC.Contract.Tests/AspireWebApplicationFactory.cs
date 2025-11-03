using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using HeroSSID.Data;
using Testcontainers.PostgreSql;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Custom WebApplicationFactory that uses Testcontainers PostgreSQL for testing
/// </summary>
#pragma warning disable CA1515 // This is a test fixture used by xUnit
public sealed class AspireWebApplicationFactory : WebApplicationFactory<Program>, IAsyncLifetime
#pragma warning restore CA1515
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder()
        .WithImage("postgres:16-alpine")
        .WithDatabase("herossid_test")
        .WithUsername("postgres")
        .WithPassword("test_password")
        .Build();

    public async Task InitializeAsync()
    {
        // Start the PostgreSQL container
        await _postgresContainer.StartAsync().ConfigureAwait(false);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Use Development environment for testing to get development certificates
        builder.UseEnvironment("Development");

        // Override configuration to use Testcontainers PostgreSQL
        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HeroDb"] = _postgresContainer.GetConnectionString(),
                ["HEROSSID_DB_PASSWORD"] = "test_password"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Remove the existing DbContext registration
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<HeroDbContext>));
            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            // Re-add DbContext with Testcontainers connection string
            services.AddDbContext<HeroDbContext>(options =>
            {
                options.UseNpgsql(_postgresContainer.GetConnectionString());
            });

            // Ensure database is created and migrations are applied
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            db.Database.EnsureCreated();
        });
    }

    public new async Task DisposeAsync()
    {
        await _postgresContainer.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
