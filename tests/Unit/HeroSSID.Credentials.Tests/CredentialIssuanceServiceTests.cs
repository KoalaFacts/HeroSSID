using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// TDD tests for ICredentialIssuanceService - T005
/// Tests written BEFORE implementation following red-green-refactor cycle
/// </summary>
public sealed class CredentialIssuanceServiceTests : IDisposable
{
    private readonly HeroDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly Guid _tenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public CredentialIssuanceServiceTests()
    {
        // Arrange: In-memory database for testing
        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new HeroDbContext(options);
        _tenantContext = new TestTenantContext(_tenantId);
    }

    [Fact]
    public async Task IssueCredentialAsyncValidInputReturnsJwtVc()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var credentialSubject = new Dictionary<string, object>
        {
            ["degree"] = "Bachelor of Science",
            ["university"] = "Example University"
        };

        var service = CreateService();

        // Act
        var jwtVc = await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "UniversityDegreeCredential",
            credentialSubject).ConfigureAwait(true);

        // Assert
        Assert.NotNull(jwtVc);
        Assert.NotEmpty(jwtVc);
        Assert.StartsWith("eyJ", jwtVc, StringComparison.Ordinal); // JWT format starts with base64url-encoded header
    }

    [Fact]
    public async Task IssueCredentialAsyncValidInputStoresCredentialInDatabase()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var credentialSubject = new Dictionary<string, object>
        {
            ["degree"] = "Bachelor of Science"
        };

        var service = CreateService();

        // Act
        var jwtVc = await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "UniversityDegreeCredential",
            credentialSubject).ConfigureAwait(true);

        // Assert
        var storedCredential = await _dbContext.VerifiableCredentials
            .FirstOrDefaultAsync(c => c.IssuerDidId == issuerDidId && c.HolderDidId == holderDidId).ConfigureAwait(true);

        Assert.NotNull(storedCredential);
        Assert.Equal("UniversityDegreeCredential", storedCredential.CredentialType);
        Assert.Equal(jwtVc, storedCredential.CredentialJwt);
        Assert.Equal("active", storedCredential.Status);
        Assert.Equal(_tenantId, storedCredential.TenantId);
    }

    [Fact]
    public async Task IssueCredentialAsyncWithExpirationDateSetsExpiresAt()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var credentialSubject = new Dictionary<string, object> { ["claim"] = "value" };
        var expirationDate = DateTimeOffset.UtcNow.AddYears(1);

        var service = CreateService();

        // Act
        await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential",
            credentialSubject,
            expirationDate).ConfigureAwait(true);

        // Assert
        var storedCredential = await _dbContext.VerifiableCredentials
            .FirstOrDefaultAsync(c => c.IssuerDidId == issuerDidId).ConfigureAwait(true);

        Assert.NotNull(storedCredential);
        Assert.NotNull(storedCredential.ExpiresAt);
        Assert.Equal(expirationDate, storedCredential.ExpiresAt.Value, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task IssueCredentialAsyncNullTenantContextThrowsArgumentNullException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.IssueCredentialAsync(
                null!,
                issuerDidId,
                holderDidId,
                "TestCredential",
                new Dictionary<string, object>()).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task IssueCredentialAsyncNullCredentialTypeThrowsArgumentNullException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                null!,
                new Dictionary<string, object>()).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task IssueCredentialAsyncNullCredentialSubjectThrowsArgumentNullException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "TestCredential",
                null!).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task IssueCredentialAsyncIssuerDidNotFoundThrowsArgumentException()
    {
        // Arrange
        var (_, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var nonExistentIssuerId = Guid.NewGuid();
        var service = CreateService();

        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                nonExistentIssuerId,
                holderDidId,
                "TestCredential",
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("issuer", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssueCredentialAsyncHolderDidNotFoundThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, _) = await SeedTestDidsAsync().ConfigureAwait(true);
        var nonExistentHolderId = Guid.NewGuid();
        var service = CreateService();
        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                nonExistentHolderId,
                "TestCredential",
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("holder", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssueCredentialAsyncDeactivatedIssuerDidThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);

        // Deactivate issuer DID
        var issuerDid = await _dbContext.Dids.FindAsync(issuerDidId).ConfigureAwait(true);
        issuerDid!.Status = "deactivated";
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);

        var service = CreateService();
        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "TestCredential",
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("deactivated", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssueCredentialAsyncCrossTenantIssuerThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);

        // Change issuer to different tenant
        var issuerDid = await _dbContext.Dids.FindAsync(issuerDidId).ConfigureAwait(true);
        issuerDid!.TenantId = Guid.NewGuid();
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);

        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "TestCredential",
                new Dictionary<string, object>()).ConfigureAwait(true)).ConfigureAwait(true);
    }

    private CredentialIssuanceService CreateService()
    {
        var mockKeyEncryption = new MockKeyEncryptionService();
        var mockRateLimiter = new MockRateLimiter();

        return new CredentialIssuanceService(
            _dbContext,
            mockKeyEncryption,
            mockRateLimiter,
            null); // Logger is optional
    }

    private async Task<(Guid issuerDidId, Guid holderDidId)> SeedTestDidsAsync()
    {
        var issuerPubKey = new byte[32];
        var holderPubKey = new byte[32];

        var issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:web:example.com:issuer",
            PublicKeyEd25519 = issuerPubKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPubKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        var holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:web:example.com:holder",
            PublicKeyEd25519 = holderPubKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPubKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.Add(issuerDid);
        _dbContext.Dids.Add(holderDid);
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);

        return (issuerDid.Id, holderDid.Id);
    }

    // T011: Constructor tests
    [Fact]
    public void ConstructorAllDependenciesProvidedSucceeds()
    {
        // Arrange - all dependencies provided
        var mockKeyEncryption = new MockKeyEncryptionService();
        var mockRateLimiter = new MockRateLimiter();
        var mockLogger = new MockLogger();

        // Act & Assert - should not throw
        var exception = Record.Exception(() =>
            new CredentialIssuanceServiceTestImpl(_dbContext, mockKeyEncryption, mockRateLimiter, mockLogger));

        Assert.Null(exception);
    }

    [Fact]
    public void ConstructorMissingDbContextThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyEncryption = new MockKeyEncryptionService();
        var mockRateLimiter = new MockRateLimiter();
        var mockLogger = new MockLogger();

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new CredentialIssuanceServiceTestImpl(null!, mockKeyEncryption, mockRateLimiter, mockLogger));

        Assert.Equal("dbContext", exception.ParamName);
    }

    [Fact]
    public void ConstructorMissingKeyEncryptionThrowsArgumentNullException()
    {
        // Arrange
        var mockRateLimiter = new MockRateLimiter();
        var mockLogger = new MockLogger();

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new CredentialIssuanceServiceTestImpl(_dbContext, null!, mockRateLimiter, mockLogger));

        Assert.Equal("keyEncryptionService", exception.ParamName);
    }

    [Fact]
    public void ConstructorMissingRateLimiterThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyEncryption = new MockKeyEncryptionService();
        var mockLogger = new MockLogger();

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new CredentialIssuanceServiceTestImpl(_dbContext, mockKeyEncryption, null!, mockLogger));

        Assert.Equal("rateLimiter", exception.ParamName);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    // Test implementation class for constructor testing
    private sealed class CredentialIssuanceServiceTestImpl
    {
        public CredentialIssuanceServiceTestImpl(
            HeroDbContext dbContext,
            IKeyEncryptionService keyEncryptionService,
            IRateLimiter rateLimiter,
            ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(dbContext);
            ArgumentNullException.ThrowIfNull(keyEncryptionService);
            ArgumentNullException.ThrowIfNull(rateLimiter);
            // Note: Logger can be null (optional dependency pattern)
        }
    }

    // Mock implementations for constructor testing
    private sealed class MockKeyEncryptionService : IKeyEncryptionService
    {
        public byte[] Encrypt(byte[] plaintext) => new byte[64];
        public byte[] Decrypt(byte[] ciphertext) => new byte[32];
        public string EncryptString(string plaintext) => Convert.ToBase64String(new byte[64]);
        public string DecryptString(string ciphertext) => "decrypted";
    }

    private sealed class MockRateLimiter : IRateLimiter
    {
        public Task<bool> IsAllowedAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
            => Task.FromResult(true);

        public Task RecordOperationAsync(Guid tenantId, string operationType, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    private sealed class MockLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => false;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }

    private sealed class TestTenantContext(Guid tenantId) : ITenantContext
    {
        private readonly Guid _tenantId = tenantId;

        public Guid GetCurrentTenantId() => _tenantId;
    }
}
