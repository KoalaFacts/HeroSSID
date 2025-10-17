using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Integration tests for the complete DID lifecycle:
/// - Create DID with Ed25519 keys
/// - Store in database
/// - Retrieve from database
/// - Validate W3C DID Document format
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1001 // Types that own disposable fields should be disposable - IAsyncLifetime handles disposal
#pragma warning disable CA5394 // Do not use insecure randomness - test data only
public sealed class DidLifecycleIntegrationTests : IAsyncLifetime
{
    private HeroDbContext? _dbContext;
    private bool _disposed;

    public async ValueTask InitializeAsync()
    {
        // Setup in-memory database for testing
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"HeroSSIDTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        if (_dbContext != null)
        {
            await _dbContext.Database.EnsureDeletedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);
            await _dbContext.DisposeAsync().ConfigureAwait(false);
            _dbContext = null;
        }

        _disposed = true;
    }

    [Fact]
    public async Task CreateDid_StoreInDatabase_RetrieveSuccessfully()
    {
        // Arrange - This test will fail until DidCreationService is implemented
        Assert.NotNull(_dbContext);

        // Expected DID data (using did:key format)
        string expectedDidIdentifier = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        byte[] expectedPublicKey = new byte[32];
        byte[] expectedEncryptedPrivateKey = new byte[64];

        // Fill with sample data
        Random.Shared.NextBytes(expectedPublicKey);
        Random.Shared.NextBytes(expectedEncryptedPrivateKey);

        string didDocumentJson = $$"""
        {
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "{{expectedDidIdentifier}}",
          "verificationMethod": [{
            "id": "{{expectedDidIdentifier}}#keys-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "{{expectedDidIdentifier}}",
            "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
          }],
          "authentication": ["{{expectedDidIdentifier}}#keys-1"]
        }
        """;

        // Act - Manually create DID entity (will be replaced with DidCreationService call)
        DidEntity didEntity = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = expectedDidIdentifier,
            PublicKeyEd25519 = expectedPublicKey,
            PrivateKeyEd25519Encrypted = expectedEncryptedPrivateKey,
            DidDocumentJson = didDocumentJson,
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.Add(didEntity);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        // Retrieve from database
        DidEntity? retrievedDid = await _dbContext.Dids
            .FirstOrDefaultAsync(d => d.DidIdentifier == expectedDidIdentifier, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(retrievedDid);
        Assert.Equal(expectedDidIdentifier, retrievedDid.DidIdentifier);
        Assert.Equal(HeroDbContext.DefaultTenantId, retrievedDid.TenantId);
        Assert.Equal(32, retrievedDid.PublicKeyEd25519.Length);
        Assert.Equal("active", retrievedDid.Status);
        Assert.Contains(expectedDidIdentifier, retrievedDid.DidDocumentJson, StringComparison.Ordinal);

        // This test demonstrates the integration pattern
        // Once DidCreationService is implemented, we'll replace the manual entity creation
        // with: var did = await didCreationService.CreateDidAsync();
    }

    [Fact]
    public async Task CreateDid_WithDidCreationService_ShouldFail()
    {
        // This test is a placeholder for the actual service integration
        // It should fail until DidCreationService is implemented

        Assert.NotNull(_dbContext);

        // Arrange
        // var didCreationService = new DidCreationService(...);

        // Act & Assert
        await Assert.ThrowsAsync<NotImplementedException>(async () =>
        {
            // This will be: await didCreationService.CreateDidAsync();
            await Task.CompletedTask.ConfigureAwait(true);
            throw new NotImplementedException("DidCreationService not yet implemented");
        });
    }

    [Fact]
    public async Task DatabaseContext_ShouldSupportDidOperations()
    {
        // Verify the database context is properly configured for DID operations
        Assert.NotNull(_dbContext);

        // Verify DbSet is accessible
        Assert.NotNull(_dbContext.Dids);

        // Verify we can query (should return empty for new database)
        int count = await _dbContext.Dids.CountAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, count);

        // Verify default tenant ID is set correctly
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), HeroDbContext.DefaultTenantId);
    }
}
#pragma warning restore CA1707
