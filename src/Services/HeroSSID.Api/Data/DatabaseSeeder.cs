using System.Security.Cryptography;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Api.Data;

/// <summary>
/// Seeds the database with development/test data (T033).
/// </summary>
internal static class DatabaseSeeder
{
    /// <summary>
    /// Seeds OAuth clients and other development data.
    /// </summary>
    public static async Task SeedDevelopmentDataAsync(
        IServiceProvider serviceProvider,
        ILogger logger)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<HeroDbContext>();

        try
        {
            // Ensure database is created
            await context.Database.EnsureCreatedAsync().ConfigureAwait(false);

            // T033: Seed test OAuth client for development
            var existingClient = await context.OAuthClients
                .FirstOrDefaultAsync(c => c.ClientId == "test_client");

            if (existingClient == null)
            {
                var client = new OAuthClient
                {
                    Id = Guid.NewGuid(),
                    ClientId = "test_client",
                    ClientSecretHash = HashSecret("test_secret"),
                    DisplayName = "Test Client (Development)",
                    TenantId = HeroDbContext.DefaultTenantId,
                    Scopes = "credential:issue credential:verify",
                    IsEnabled = true,
                    CreatedAt = DateTimeOffset.UtcNow
                };

                context.OAuthClients.Add(client);
                await context.SaveChangesAsync().ConfigureAwait(false);

                logger.LogInformation("Seeded test OAuth client: test_client");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error seeding database");
            throw;
        }
    }

    /// <summary>
    /// Hash a client secret using PBKDF2.
    /// </summary>
    private static string HashSecret(string secret)
    {
        // Generate a random salt
        byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);

        // Hash the secret with PBKDF2
        byte[] hash = KeyDerivation.Pbkdf2(
            password: secret,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8);

        // Combine salt and hash for storage
        byte[] hashBytes = new byte[salt.Length + hash.Length];
        Array.Copy(salt, 0, hashBytes, 0, salt.Length);
        Array.Copy(hash, 0, hashBytes, salt.Length, hash.Length);

        return Convert.ToBase64String(hashBytes);
    }
}
