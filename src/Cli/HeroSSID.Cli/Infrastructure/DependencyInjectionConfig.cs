using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Services;
using HeroSSID.Data;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Cli.Infrastructure;

/// <summary>
/// Dependency injection configuration for HeroSSID CLI
/// </summary>
internal static class DependencyInjectionConfig
{
    public static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        // Database
        var connectionString = configuration.GetConnectionString("HeroDb")
            ?? throw new InvalidOperationException("Database connection string 'HeroDb' not found");

        services.AddDbContext<HeroDbContext>(options =>
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure(maxRetryCount: 3);
                npgsqlOptions.MigrationsAssembly(typeof(HeroDbContext).Assembly.FullName);
            });
        });

        // Data Protection for encryption
        var keyStoragePath = configuration["Encryption:KeyStoragePath"] ?? "./keys";
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(keyStoragePath))
            .SetApplicationName("HeroSSID");

        // Core services
        services.AddSingleton<IKeyEncryptionService, LocalKeyEncryptionService>();

        // DID Operations services
        services.AddScoped<IDidCreationService, DidCreationService>();

        // Add structured logger
        services.AddSingleton(typeof(HeroSSID.Observability.StructuredLogger<>));
    }
}
