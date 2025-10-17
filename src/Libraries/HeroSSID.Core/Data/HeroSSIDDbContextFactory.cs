using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HeroSSID.Core.Data;

/// <summary>
/// Design-time factory for creating DbContext instances for EF Core tools (migrations)
/// </summary>
public sealed class HeroSSIDDbContextFactory : IDesignTimeDbContextFactory<HeroSSIDDbContext>
{
    public HeroSSIDDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<HeroSSIDDbContext>();

        // Use a dummy connection string for design-time operations
        // The actual connection string will be provided at runtime
        optionsBuilder.UseNpgsql(
            "Host=localhost;Database=herossid_dev;Username=herossid;Password=dev_password",
            npgsqlOptions => npgsqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", "public"));

        return new HeroSSIDDbContext(optionsBuilder.Options);
    }
}
