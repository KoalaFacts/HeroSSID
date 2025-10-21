using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.MvpImplementations;
using HeroSSID.Core.KeyEncryption;
using HeroSSID.Core.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Security edge case tests for W3C Verifiable Credentials implementation
/// Tests extreme scenarios, attack vectors, and resource limits
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1859 // Concrete types for performance - prefer interfaces for testability
public sealed class SecurityEdgeCaseTests : IDisposable
{
    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _keyEncryptionService;
    private readonly ITenantContext _tenantContext;
    private readonly Guid _tenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public SecurityEdgeCaseTests()
    {
        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new HeroDbContext(options);

        var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        _keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        _tenantContext = new TestTenantContext(_tenantId);
    }

    [Fact]
    public async Task RateLimitExhaustion_ExceedingMaxOperations_ThrowsInvalidOperationException()
    {
        // Arrange - Create rate limiter with strict limits for testing
        var rateLimiter = new InMemoryRateLimiter(
            windowSize: TimeSpan.FromSeconds(60),
            maxOperations: 3); // Very low limit for testing

        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act - Issue credentials up to the limit
        await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential1",
            credentialSubject).ConfigureAwait(true);

        await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential2",
            credentialSubject).ConfigureAwait(true);

        await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential3",
            credentialSubject).ConfigureAwait(true);

        // Assert - 4th attempt should exceed rate limit
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "TestCredential4",
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("rate limit", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LargeCredentialSubjectPayload_ExceedingSize100KB_ThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        // Create a large payload exceeding 100KB
        var largePayload = new Dictionary<string, object>();
        var largeString = new string('X', 110 * 1024); // 110KB string
        largePayload["largeData"] = largeString;

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "LargeCredential",
                largePayload).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("credential subject payload exceeds maximum size", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LargeCredentialSubjectPayload_AtBoundary100KB_Succeeds()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        // Create a payload just under 100KB
        var payload = new Dictionary<string, object>();
        var largeString = new string('X', 95 * 1024); // 95KB string - safely under limit
        payload["data"] = largeString;

        // Act
        var jwtVc = await service.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "BoundaryCredential",
            payload).ConfigureAwait(true);

        // Assert
        Assert.NotNull(jwtVc);
        Assert.NotEmpty(jwtVc);
    }

    [Fact]
    public async Task MalformedJwtAttack_InvalidFormat_VerificationFails()
    {
        // Arrange
        var rateLimiter = new InMemoryRateLimiter();
        var verificationService = new CredentialVerificationService(
            _dbContext,
            rateLimiter);

        // Act - Completely malformed JWT
        var malformedJwt = "not.a.valid.jwt.format";
        var result = await verificationService.VerifyCredentialAsync(
            _tenantContext,
            malformedJwt).ConfigureAwait(true);

        // Assert - Verification should fail gracefully
        Assert.False(result.IsValid);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task MalformedJwtAttack_TwoPartJwt_VerificationFails()
    {
        // Arrange
        var rateLimiter = new InMemoryRateLimiter();
        var verificationService = new CredentialVerificationService(
            _dbContext,
            rateLimiter);

        // Act - JWT with only 2 parts (missing signature)
        var twoPartJwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0";
        var result = await verificationService.VerifyCredentialAsync(
            _tenantContext,
            twoPartJwt).ConfigureAwait(true);

        // Assert - Verification should fail gracefully
        Assert.False(result.IsValid);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task MalformedJwtAttack_InvalidBase64_VerificationFails()
    {
        // Arrange
        var rateLimiter = new InMemoryRateLimiter();
        var verificationService = new CredentialVerificationService(
            _dbContext,
            rateLimiter);

        // Act - JWT with invalid base64 encoding
        var invalidBase64Jwt = "!!!invalid!!!.base64!!!.encoding!!!";
        var result = await verificationService.VerifyCredentialAsync(
            _tenantContext,
            invalidBase64Jwt).ConfigureAwait(true);

        // Assert - Verification should fail gracefully
        Assert.False(result.IsValid);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task MalformedJwtAttack_TamperedSignature_VerificationFails()
    {
        // Arrange - Issue a valid credential first
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var issuanceService = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var verificationService = new CredentialVerificationService(
            _dbContext,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };
        var validJwt = await issuanceService.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential",
            credentialSubject).ConfigureAwait(true);

        // Act - Tamper with the signature
        var jwtParts = validJwt.Split('.');
        var tamperedSignature = jwtParts[2].Replace('a', 'b').Replace('A', 'B');
        var tamperedJwt = $"{jwtParts[0]}.{jwtParts[1]}.{tamperedSignature}";

        // Assert - Verification should fail due to invalid signature
        var result = await verificationService.VerifyCredentialAsync(
            _tenantContext,
            tamperedJwt).ConfigureAwait(true);

        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.SignatureInvalid, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact(Skip = "DbContext is not thread-safe - concurrent operations require separate context instances")]
    public async Task ConcurrentCredentialIssuance_RaceConditions_AllSucceedWithoutConflicts()
    {
        // NOTE: This test documents the limitation that EF Core DbContext is not thread-safe
        // In production, each request would have its own DbContext via DI scoping

        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter(maxOperations: 50); // High enough for concurrent operations
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object>
        {
            ["test"] = "concurrent"
        };

        // Act - Issue 10 credentials concurrently
        const int concurrentCount = 10;
        var tasks = new List<Task<string>>();

        for (int i = 0; i < concurrentCount; i++)
        {
            int index = i; // Capture for closure
            tasks.Add(Task.Run(async () =>
                await service.IssueCredentialAsync(
                    _tenantContext,
                    issuerDidId,
                    holderDidId,
                    $"ConcurrentCredential{index}",
                    credentialSubject).ConfigureAwait(true)));
        }

        var results = await Task.WhenAll(tasks).ConfigureAwait(true);

        // Assert - All credentials should be issued successfully
        Assert.Equal(concurrentCount, results.Length);
        Assert.All(results, jwt =>
        {
            Assert.NotNull(jwt);
            Assert.NotEmpty(jwt);
        });

        // Verify all credentials are unique
        var uniqueJwts = results.Distinct().Count();
        Assert.Equal(concurrentCount, uniqueJwts);

        // Verify database contains all credentials
        var storedCredentials = await _dbContext.VerifiableCredentials
            .Where(c => c.IssuerDidId == issuerDidId)
            .ToListAsync().ConfigureAwait(true);

        Assert.Equal(concurrentCount, storedCredentials.Count);
    }

    [Fact(Skip = "DbContext is not thread-safe - concurrent operations require separate context instances")]
    public async Task ConcurrentVerification_MultipleThreads_AllSucceed()
    {
        // NOTE: This test documents the limitation that EF Core DbContext is not thread-safe
        // In production, each request would have its own DbContext via DI scoping

        // Arrange - Issue a credential first
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter(maxOperations: 100);
        var issuanceService = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var verificationService = new CredentialVerificationService(
            _dbContext,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object> { ["test"] = "concurrent" };
        var jwtVc = await issuanceService.IssueCredentialAsync(
            _tenantContext,
            issuerDidId,
            holderDidId,
            "TestCredential",
            credentialSubject).ConfigureAwait(true);

        // Act - Verify the same credential concurrently from multiple threads
        const int concurrentCount = 20;
        var tasks = Enumerable.Range(0, concurrentCount)
            .Select(_ => Task.Run(async () =>
                await verificationService.VerifyCredentialAsync(
                    _tenantContext,
                    jwtVc).ConfigureAwait(true)))
            .ToArray();

        var results = await Task.WhenAll(tasks).ConfigureAwait(true);

        // Assert - All verifications should succeed with consistent results
        Assert.Equal(concurrentCount, results.Length);
        Assert.All(results, result =>
        {
            Assert.True(result.IsValid);
            Assert.Equal(VerificationStatus.Valid, result.Status);
        });
    }

    [Fact]
    public async Task EmptyCredentialSubject_ThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var emptySubject = new Dictionary<string, object>();

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                "EmptyCredential",
                emptySubject).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Contains("credential subject cannot be empty", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NullCredentialType_ThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                null!,
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task EmptyCredentialType_ThrowsArgumentException()
    {
        // Arrange
        var (issuerDidId, holderDidId) = await SeedTestDidsAsync().ConfigureAwait(true);
        var rateLimiter = new InMemoryRateLimiter();
        var service = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            rateLimiter);

        var credentialSubject = new Dictionary<string, object> { ["test"] = "value" };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.IssueCredentialAsync(
                _tenantContext,
                issuerDidId,
                holderDidId,
                string.Empty,
                credentialSubject).ConfigureAwait(true)).ConfigureAwait(true);
    }

    private async Task<(Guid issuerDidId, Guid holderDidId)> SeedTestDidsAsync()
    {
        using Key issuerKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] issuerPublicKey = issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] issuerPrivateKey = issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] issuerEncryptedPrivateKey = _keyEncryptionService.Encrypt(issuerPrivateKey);

        using Key holderKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] holderPrivateKey = holderKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] holderEncryptedPrivateKey = _keyEncryptionService.Encrypt(holderPrivateKey);

        var issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:test:security:issuer",
            PublicKeyEd25519 = issuerPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPublicKey),
            PrivateKeyEd25519Encrypted = issuerEncryptedPrivateKey,
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        var holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:test:security:holder",
            PublicKeyEd25519 = holderPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = holderEncryptedPrivateKey,
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.Add(issuerDid);
        _dbContext.Dids.Add(holderDid);
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(issuerPrivateKey);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(holderPrivateKey);

        return (issuerDid.Id, holderDid.Id);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private sealed class TestTenantContext : ITenantContext
    {
        private readonly Guid _tenantId;
        public TestTenantContext(Guid tenantId) => _tenantId = tenantId;
        public Guid GetCurrentTenantId() => _tenantId;
    }
}
#pragma warning restore CA1859
#pragma warning restore CA1707
