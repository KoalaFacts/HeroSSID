using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HeroSSID.Data;

/// <summary>
/// Design-time factory for EF Core migrations
/// Used by dotnet ef migrations commands
/// </summary>
public sealed class HeroDbContextFactory : IDesignTimeDbContextFactory<HeroDbContext>
{
    public HeroDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<HeroDbContext>();

        // Use connection string from environment or default to localhost
        var connectionString = Environment.GetEnvironmentVariable("HEROSSID_DB_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=herossid;Username=herossid;Password=CHANGE_ME_IN_PRODUCTION";

        optionsBuilder.UseNpgsql(connectionString, npgsqlOptions =>
        {
            npgsqlOptions.MigrationsAssembly(typeof(HeroDbContext).Assembly.FullName);
            npgsqlOptions.EnableRetryOnFailure(maxRetryCount: 3);
        });

        return new HeroDbContext(optionsBuilder.Options);
    }
}
