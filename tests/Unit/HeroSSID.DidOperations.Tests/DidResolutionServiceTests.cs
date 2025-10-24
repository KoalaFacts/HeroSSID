using HeroSSID.DidOperations.DidMethod;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// Unit tests for DidResolutionService
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1001 // Types that own disposable fields should be disposable - IAsyncLifetime handles disposal
public sealed class DidResolutionServiceTests : IAsyncLifetime
{
    private HeroDbContext? _dbContext;
    private IKeyEncryptionService? _mockEncryption;
    private ITenantContext? _mockTenantContext;
    private DidMethodResolver? _didMethodResolver;
    private ILogger<DidCreationService>? _mockDidCreationLogger;
    private ILogger<DidResolutionService>? _mockResolutionLogger;
    private DidCreationService? _didCreationService;
    private bool _disposed;

    public async ValueTask InitializeAsync()
    {
        // Setup in-memory database
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"DidResolutionTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);

        // Setup mocked encryption service
        _mockEncryption = Substitute.For<IKeyEncryptionService>();
        _mockEncryption.Encrypt(Arg.Any<byte[]>()).Returns(callInfo =>
        {
            byte[] input = callInfo.Arg<byte[]>();
            byte[] encrypted = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                encrypted[i] = (byte)(input[i] ^ 0x5A);
            }
            return encrypted;
        });

        // Setup mocked tenant context
        _mockTenantContext = Substitute.For<ITenantContext>();
        _mockTenantContext.GetCurrentTenantId().Returns(Guid.Parse("11111111-1111-1111-1111-111111111111"));

        // Setup loggers
        _mockDidCreationLogger = Substitute.For<ILogger<DidCreationService>>();
        _mockResolutionLogger = Substitute.For<ILogger<DidResolutionService>>();

        // Setup DID method resolver
        IDidMethod[] didMethods = new IDidMethod[]
        {
            new DidKeyMethod(),
            new DidWebMethod()
        };
        _didMethodResolver = new DidMethodResolver(didMethods);

        // Create DID creation service for test setup
        _didCreationService = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockDidCreationLogger);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        if (_dbContext != null)
        {
            await _dbContext.DisposeAsync().ConfigureAwait(false);
        }

        _disposed = true;
    }

    [Fact]
    public async Task ResolveAsync_WithValidDid_ShouldReturnDidDocument()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);
        Assert.NotNull(_didCreationService);

        // Create a DID first
        var createResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);

        // Act
        var result = await service.ResolveAsync(createResult.DidIdentifier, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.DidDocument);
        Assert.Equal(createResult.DidIdentifier, result.DidIdentifier);
        Assert.Null(result.Metadata.Error);
    }

    [Fact]
    public async Task ResolveAsync_WithNonExistentDid_ShouldReturnNotFoundError()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);
        string nonExistentDid = "did:key:z6MknonExistent";

        // Act
        var result = await service.ResolveAsync(nonExistentDid, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Null(result.DidDocument);
        Assert.Equal("notFound", result.Metadata.Error);
        Assert.NotNull(result.Metadata.ErrorMessage);
    }

    [Fact]
    public async Task ResolveAsync_WithInvalidDidFormat_ShouldReturnInvalidDidError()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);
        string invalidDid = "not-a-did";

        // Act
        var result = await service.ResolveAsync(invalidDid, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Null(result.DidDocument);
        Assert.Equal("invalidDid", result.Metadata.Error);
    }

    [Fact]
    public async Task ExistsAsync_WithExistingDid_ShouldReturnTrue()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);
        Assert.NotNull(_didCreationService);

        var createResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);

        // Act
        bool exists = await service.ExistsAsync(createResult.DidIdentifier, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public async Task ExistsAsync_WithNonExistentDid_ShouldReturnFalse()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);
        string nonExistentDid = "did:key:z6MknonExistent";

        // Act
        bool exists = await service.ExistsAsync(nonExistentDid, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(exists);
    }

    [Fact]
    public async Task GetByIdAsync_WithValidId_ShouldReturnDidRetrievalResult()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);
        Assert.NotNull(_didCreationService);

        var createResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);

        // Act
        var result = await service.GetByIdAsync(createResult.Id, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(createResult.Id, result.Id);
        Assert.Equal(createResult.DidIdentifier, result.DidIdentifier);
        Assert.Equal(32, result.PublicKey.Length);
    }

    [Fact]
    public async Task GetByIdAsync_WithNonExistentId_ShouldReturnNull()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);
        Guid nonExistentId = Guid.NewGuid();

        // Act
        var result = await service.GetByIdAsync(nonExistentId, TestContext.Current.CancellationToken);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveAsync_WithNullDid_ShouldThrowArgumentException()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);

        // Act & Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type - testing null handling
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.ResolveAsync(null, TestContext.Current.CancellationToken).ConfigureAwait(true));
#pragma warning restore CS8625
    }

    [Fact]
    public async Task ExistsAsync_WithNullDid_ShouldThrowArgumentException()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_didMethodResolver);
        Assert.NotNull(_mockResolutionLogger);

        DidResolutionService service = new DidResolutionService(_dbContext, _mockTenantContext, _didMethodResolver, _mockResolutionLogger);

        // Act & Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type - testing null handling
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.ExistsAsync(null, TestContext.Current.CancellationToken).ConfigureAwait(true));
#pragma warning restore CS8625
    }
}
#pragma warning restore CA1001
#pragma warning restore CA1707
