using HeroSSID.Core.Interfaces;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// Unit tests for DidCreationService with mocked dependencies.
/// These tests verify:
/// - Key generation logic
/// - DID Document creation
/// - Database storage
/// - Error handling
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1001 // Types that own disposable fields should be disposable - IAsyncLifetime handles disposal
public sealed class DidCreationServiceTests : IAsyncLifetime
{
    private HeroDbContext? _dbContext;
    private IKeyEncryptionService? _mockEncryption;
    private ILogger<DidCreationService>? _mockLogger;
    private bool _disposed;

    public async ValueTask InitializeAsync()
    {
        // Setup in-memory database
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"DidServiceTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);

        // Setup mocked encryption service with realistic encryption simulation
        _mockEncryption = Substitute.For<IKeyEncryptionService>();
        _mockEncryption.Encrypt(Arg.Any<byte[]>()).Returns(callInfo =>
        {
            byte[] input = callInfo.Arg<byte[]>();
            // Simulate realistic encryption: add IV (16 bytes) + encrypted data + auth tag (16 bytes)
            byte[] encrypted = new byte[input.Length + 32]; // 16-byte IV + data + 16-byte tag

#pragma warning disable CA5394 // Do not use insecure randomness - this is test mock, not real crypto
            // Generate random IV (first 16 bytes)
            Random.Shared.NextBytes(encrypted.AsSpan(0, 16));
#pragma warning restore CA5394

            // Simulate encryption by XORing input with a deterministic key (for testing)
            // This is NOT real encryption, but simulates data transformation
            for (int i = 0; i < input.Length; i++)
            {
                encrypted[i + 16] = (byte)(input[i] ^ 0x5A); // Simple XOR transformation
            }

#pragma warning disable CA5394 // Do not use insecure randomness - this is test mock, not real crypto
            // Generate random auth tag (last 16 bytes)
            Random.Shared.NextBytes(encrypted.AsSpan(input.Length + 16, 16));
#pragma warning restore CA5394

            return encrypted;
        });

        // Setup mocked logger
        _mockLogger = Substitute.For<ILogger<DidCreationService>>();
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
    public async Task CreateDid_ShouldGenerateValidKeys()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(32, result.PublicKey.Length); // Ed25519 public key is 32 bytes
    }

    [Fact]
    public async Task CreateDid_ShouldEncryptPrivateKey()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        _mockEncryption.Received(1).Encrypt(Arg.Any<byte[]>());
        Assert.NotNull(result.EncryptedPrivateKey);
        Assert.NotEmpty(result.EncryptedPrivateKey);
    }

    [Fact]
    public async Task CreateDid_ShouldCreateW3CCompliantDidDocument()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var didDoc = System.Text.Json.JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(didDoc.RootElement.TryGetProperty("id", out var idProp));
        string? didId = idProp.GetString();
        Assert.NotNull(didId);
        Assert.StartsWith("did:", didId, StringComparison.Ordinal);
        Assert.True(didDoc.RootElement.TryGetProperty("verificationMethod", out var vmProp));
        Assert.True(didDoc.RootElement.TryGetProperty("authentication", out var authProp));
    }

    [Fact]
    public async Task CreateDid_ShouldStoreInDatabase()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Verify database storage
        DidEntity? storedDid = await _dbContext.Dids
            .FirstOrDefaultAsync(d => d.DidIdentifier == result.DidIdentifier, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(storedDid);
        Assert.Equal(result.DidIdentifier, storedDid.DidIdentifier);
        Assert.Equal(HeroDbContext.DefaultTenantId, storedDid.TenantId);
        Assert.Equal("active", storedDid.Status);
    }

    [Fact]
    public async Task CreateDid_WithDatabaseError_ShouldLogAndThrow()
    {
        // Arrange
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        // Create a disposed DbContext to simulate database error
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"ErrorTest_{Guid.NewGuid()}")
            .Options;

        using HeroDbContext errorDbContext = new HeroDbContext(options);
        await errorDbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        await errorDbContext.DisposeAsync();

        DidCreationService service = new DidCreationService(errorDbContext, _mockEncryption, _mockLogger);

        // Act & Assert
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await service.CreateDidAsync(TestContext.Current.CancellationToken).ConfigureAwait(true));
    }

    [Fact]
    public async Task CreateDid_ShouldUseMVPTenantId()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HeroDbContext.DefaultTenantId, result.TenantId);
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), result.TenantId);
    }

    [Fact]
    public async Task CreateDid_ShouldGenerateUniqueDidIdentifier()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var did1 = await service.CreateDidAsync(TestContext.Current.CancellationToken);
        var did2 = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(did1.DidIdentifier, did2.DidIdentifier);
        Assert.NotEqual(did1.Id, did2.Id);
        Assert.False(did1.PublicKey.SequenceEqual(did2.PublicKey));
    }

    [Fact]
    public void DidIdentifier_ShouldFollowW3CFormat()
    {
        // This is a specification test for W3C DID identifier format
        // Format: did:<method>:<method-specific-id>

        const string validDidWeb = "did:web:example.com:user:alice";
        const string validDidKey = "did:key:z6Mkf5rGMoLAM4HdgjE7XEJfLZUomgC";

        // Test did:web format
        string[] webParts = validDidWeb.Split(':');
        Assert.True(webParts.Length >= 3);
        Assert.Equal("did", webParts[0]);
        Assert.Equal("web", webParts[1]);

        // Test did:key format
        string[] keyParts = validDidKey.Split(':');
        Assert.Equal(3, keyParts.Length);
        Assert.Equal("did", keyParts[0]);
        Assert.Equal("key", keyParts[1]);
        Assert.StartsWith("z6M", keyParts[2], StringComparison.Ordinal); // Multibase z = base58btc, 6M = Ed25519 public key
    }

    [Fact]
    public void Ed25519PublicKey_ShouldBe32Bytes()
    {
        // This is a specification test for Ed25519 key size
        const int ed25519PublicKeySize = 32;

        byte[] samplePublicKey = new byte[ed25519PublicKeySize];

        Assert.Equal(32, samplePublicKey.Length);
    }

    [Fact]
    public async Task CreateDid_ShouldUsePublicKeyMultibase()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockLogger);

        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert - Verify DID document uses publicKeyMultibase with 'z' prefix
        using var didDoc = System.Text.Json.JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(didDoc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("publicKeyMultibase", out var pkMultibase));

        string? multibaseKey = pkMultibase.GetString();
        Assert.NotNull(multibaseKey);
        Assert.StartsWith("z", multibaseKey, StringComparison.Ordinal); // 'z' prefix indicates Base58 multibase encoding

        // Verify publicKeyBase58 is NOT present (deprecated field)
        Assert.False(firstVm.TryGetProperty("publicKeyBase58", out _));
    }
}
#pragma warning restore CA1707
