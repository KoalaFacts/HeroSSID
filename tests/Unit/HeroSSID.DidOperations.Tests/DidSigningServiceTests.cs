using HeroSSID.DidOperations.DidMethod;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.DidOperations.DidSigning;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// Unit tests for DidSigningService
/// Tests Ed25519 signing and verification operations
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1001 // Types that own disposable fields should be disposable - IAsyncLifetime handles disposal
public sealed class DidSigningServiceTests : IAsyncLifetime
{
    private HeroDbContext? _dbContext;
    private IKeyEncryptionService? _mockEncryption;
    private ILogger<DidSigningService>? _mockLogger;
    private DidCreationService? _didCreationService;
    private ITenantContext? _mockTenantContext;
    private bool _disposed;

    public async ValueTask InitializeAsync()
    {
        // Setup in-memory database
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"DidSigningTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);

        // Setup mocked encryption service with realistic encryption simulation
        _mockEncryption = Substitute.For<IKeyEncryptionService>();
        _mockEncryption.Encrypt(Arg.Any<byte[]>()).Returns(callInfo =>
        {
            byte[] input = callInfo.Arg<byte[]>();
            // Simple XOR encryption for testing
            byte[] encrypted = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                encrypted[i] = (byte)(input[i] ^ 0x5A);
            }
            return encrypted;
        });
        _mockEncryption.Decrypt(Arg.Any<byte[]>()).Returns(callInfo =>
        {
            byte[] input = callInfo.Arg<byte[]>();
            // Simple XOR decryption (same as encryption with XOR)
            byte[] decrypted = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                decrypted[i] = (byte)(input[i] ^ 0x5A);
            }
            return decrypted;
        });

        // Setup mocked tenant context
        _mockTenantContext = Substitute.For<ITenantContext>();
        _mockTenantContext.GetCurrentTenantId().Returns(Guid.Parse("11111111-1111-1111-1111-111111111111"));

        // Setup mocked loggers
        _mockLogger = Substitute.For<ILogger<DidSigningService>>();
        var mockDidCreationLogger = Substitute.For<ILogger<DidCreationService>>();

        // Setup DID method resolver with did:key and did:web implementations
        IDidMethod[] didMethods = new IDidMethod[]
        {
            new DidKeyMethod(),
            new DidWebMethod()
        };
        var didMethodResolver = new DidMethodResolver(didMethods);

        // Create DID creation service for test setup
        _didCreationService = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, didMethodResolver, mockDidCreationLogger);
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
    public async Task SignAsync_ShouldCreateValidSignature()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        // Create a DID first
        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] testMessage = System.Text.Encoding.UTF8.GetBytes("Hello, HeroSSID!");

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act
        byte[] signature = await signingService.SignAsync(didResult.DidIdentifier, testMessage, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length); // Ed25519 signatures are 64 bytes
        Assert.False(signature.All(b => b == 0)); // Signature should not be all zeros
    }

    [Fact]
    public async Task SignAndVerify_ShouldSucceed()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        // Create a DID
        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] testMessage = System.Text.Encoding.UTF8.GetBytes("Test message for signing");

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act - Sign message
        byte[] signature = await signingService.SignAsync(didResult.DidIdentifier, testMessage, TestContext.Current.CancellationToken);

        // Act - Verify signature
        bool isValid = await signingService.VerifyAsync(didResult.DidIdentifier, testMessage, signature, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task VerifyAsync_WithTamperedMessage_ShouldFail()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] originalMessage = System.Text.Encoding.UTF8.GetBytes("Original message");
        byte[] tamperedMessage = System.Text.Encoding.UTF8.GetBytes("Tampered message");

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Sign original message
        byte[] signature = await signingService.SignAsync(didResult.DidIdentifier, originalMessage, TestContext.Current.CancellationToken);

        // Act - Try to verify with tampered message
        bool isValid = await signingService.VerifyAsync(didResult.DidIdentifier, tamperedMessage, signature, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_WithInvalidSignature_ShouldFail()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] message = System.Text.Encoding.UTF8.GetBytes("Test message");
        byte[] invalidSignature = new byte[64]; // All zeros - invalid signature

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act
        bool isValid = await signingService.VerifyAsync(didResult.DidIdentifier, message, invalidSignature, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyWithPublicKey_ShouldWork()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] message = System.Text.Encoding.UTF8.GetBytes("Test message");

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Sign message
        byte[] signature = await signingService.SignAsync(didResult.DidIdentifier, message, TestContext.Current.CancellationToken);

        // Act - Verify using public key directly (not from database)
        bool isValid = signingService.VerifyWithPublicKey(didResult.PublicKey, message, signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task SignAsync_WithInvalidDid_ShouldThrow()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);
        byte[] message = System.Text.Encoding.UTF8.GetBytes("Test");

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await signingService.SignAsync("did:key:zNonExistent", message, TestContext.Current.CancellationToken).ConfigureAwait(true));
    }

    [Fact]
    public void VerifyWithPublicKey_WithWrongKeySize_ShouldThrow()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);
        byte[] invalidPublicKey = new byte[16]; // Wrong size - should be 32 bytes
        byte[] message = System.Text.Encoding.UTF8.GetBytes("Test");
        byte[] signature = new byte[64];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            signingService.VerifyWithPublicKey(invalidPublicKey, message, signature));
    }

    [Fact]
    public void VerifyWithPublicKey_WithWrongSignatureSize_ShouldThrow()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);
        byte[] publicKey = new byte[32];
        byte[] message = System.Text.Encoding.UTF8.GetBytes("Test");
        byte[] invalidSignature = new byte[32]; // Wrong size - should be 64 bytes

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            signingService.VerifyWithPublicKey(publicKey, message, invalidSignature));
    }

    [Fact]
    public async Task SignAsync_MultipleMessages_ShouldProduceDifferentSignatures()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_mockEncryption);
        Assert.NotNull(_mockTenantContext);
        Assert.NotNull(_mockLogger);
        Assert.NotNull(_didCreationService);

        var didResult = await _didCreationService.CreateDidAsync(TestContext.Current.CancellationToken);
        byte[] message1 = System.Text.Encoding.UTF8.GetBytes("Message 1");
        byte[] message2 = System.Text.Encoding.UTF8.GetBytes("Message 2");

        var signingService = new DidSigningService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act
        byte[] signature1 = await signingService.SignAsync(didResult.DidIdentifier, message1, TestContext.Current.CancellationToken);
        byte[] signature2 = await signingService.SignAsync(didResult.DidIdentifier, message2, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(signature1, signature2);
    }
}
#pragma warning restore CA1707
#pragma warning restore CA1001
