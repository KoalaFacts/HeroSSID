using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Services;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
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
        // Use OS-specific secure storage by default, or override with absolute path
        string? configuredPath = configuration["Encryption:KeyStoragePath"];
        string keyStoragePath;

        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            // Use OS-specific secure application data directory
            string appData = Environment.GetFolderPath(
                Environment.SpecialFolder.ApplicationData,
                Environment.SpecialFolderOption.Create);
            keyStoragePath = Path.Combine(appData, "HeroSSID", "keys");
        }
        else
        {
            // Use configured absolute path
            keyStoragePath = configuredPath;
        }

        var keyDirectory = new DirectoryInfo(keyStoragePath);
        if (!keyDirectory.Exists)
        {
            keyDirectory.Create();
            // Note: Consider setting ACLs here for production scenarios
        }

        // SECURITY: Configure Data Protection API with persistent file-based key storage
        // Keys are encrypted at rest by the OS (DPAPI on Windows, keychain on macOS, etc.)
        services.AddDataProtection()
            .PersistKeysToFileSystem(keyDirectory)
            .SetApplicationName("HeroSSID")
            .SetDefaultKeyLifetime(TimeSpan.FromDays(90)); // Rotate keys every 90 days

        // Core services
        services.AddSingleton<IKeyEncryptionService, LocalKeyEncryptionService>();
        services.AddSingleton<ITenantContext, DefaultTenantContext>(); // MVP: Single tenant

        // DID Method implementations
        services.AddSingleton<IDidMethod, DidKeyMethod>();
        services.AddSingleton<IDidMethod, DidWebMethod>();
        services.AddSingleton<DidMethodResolver>();

        // DID Operations services
        services.AddScoped<IDidCreationService, DidCreationService>();
        services.AddScoped<IDidResolutionService, DidResolutionService>();
        services.AddScoped<IDidSigningService, DidSigningService>();

        // Add structured logger
        services.AddSingleton(typeof(HeroSSID.Observability.StructuredLogger<>));
    }
}
