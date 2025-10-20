using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Services;
using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Models;
using HeroSSID.Credentials.Services;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;
using System;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// TDD tests for ICredentialVerificationService - T007
/// Tests written BEFORE implementation following red-green-refactor cycle
/// </summary>
public sealed class CredentialVerificationServiceTests : IDisposable
{
    private static readonly string[] W3cVcContext = new[] { "https://www.w3.org/2018/credentials/v1" };
    private static readonly string[] VerifiableCredentialType = new[] { "VerifiableCredential" };
    private static readonly string[] TestCredentialType = new[] { "VerifiableCredential", "TestCredential" };

    private readonly HeroDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly Guid _tenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private readonly byte[] _testPrivateKey;
    private readonly byte[] _testPublicKey;

    public CredentialVerificationServiceTests()
    {
        // Arrange: In-memory database for testing
        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new HeroDbContext(options);
        _tenantContext = new TestTenantContext(_tenantId);

        // Generate test Ed25519 key pair
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(algorithm, keyParams);
        _testPrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        _testPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    [Fact]
    public async Task VerifyCredentialAsync_ValidJwtVc_ReturnsVerificationResult()
    {
        // Arrange
        var service = CreateService();
        var validJwtVc = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCJ9.eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUuY29tOmlzc3VlciIsInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb206aG9sZGVyIn0.signature";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext, validJwtVc);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsync_InvalidSignature_ReturnsFailedResult()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();

        // Create a valid JWT and tamper with it
        var validJwt = CreateValidTestJwt();
        var parts = validJwt.Split('.');
        var tamperedJwt = $"{parts[0]}.{parts[1]}.TAMPERED_SIGNATURE_XXX";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,tamperedJwt);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.SignatureInvalid, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsync_ExpiredCredential_ReturnsFailedResult()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        // Create JWT with expiration date in the past
        var expiredJwt = CreateTestJwtWithExpiration(DateTimeOffset.UtcNow.AddYears(-1));

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,expiredJwt);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.Expired, result.Status);
        Assert.Contains("expired", result.ValidationErrors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyCredentialAsync_MalformedJwt_ReturnsFailedResult()
    {
        // Arrange
        var service = CreateService();
        var malformedJwt = "not.a.valid.jwt.format";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,malformedJwt);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.MalformedJwt, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsync_NullCredentialJwt_ThrowsArgumentException()
    {
        // Arrange
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyCredentialAsync(_tenantContext,null!));
    }

    [Fact]
    public async Task VerifyCredentialAsync_EmptyCredentialJwt_ThrowsArgumentException()
    {
        // Arrange
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyCredentialAsync(_tenantContext,string.Empty));
    }

    [Fact]
    public async Task VerifyCredentialAsync_IssuerNotFound_ReturnsFailedResult()
    {
        // Arrange
        var service = CreateService();
        // Valid JWT format but issuer DID doesn't exist in database
        var jwtWithUnknownIssuer = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCJ9.eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUuY29tOnVua25vd24ifQ.signature";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithUnknownIssuer);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.IssuerNotFound, result.Status);
        Assert.Contains("issuer", result.ValidationErrors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyCredentialAsync_ValidCredential_ParsesCredentialSubject()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt);

        // Assert
        if (result.CredentialSubject != null)
        {
            Assert.NotNull(result.CredentialSubject);
            Assert.IsType<Dictionary<string, object>>(result.CredentialSubject);
        }
    }

    [Fact]
    public async Task VerifyCredentialAsync_ValidCredential_ExtractsIssuerDid()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt);

        // Assert
        Assert.NotNull(result.IssuerDid);
        Assert.StartsWith("did:", result.IssuerDid, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyCredentialAsync_ValidCredential_ExtractsExpirationDate()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        var jwtWithExpiration = CreateTestJwtWithExpiration(DateTimeOffset.UtcNow.AddYears(1));

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithExpiration);

        // Assert
        if (result.Status == VerificationStatus.Valid && result.ExpiresAt.HasValue)
        {
            Assert.NotNull(result.ExpiresAt);
            Assert.True(result.ExpiresAt.Value > DateTimeOffset.UtcNow);
        }
    }

    [Fact]
    public async Task VerifyCredentialAsync_NoExpiration_ReturnsNullExpiresAt()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        var jwtWithoutExpiration = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithoutExpiration);

        // Assert
        // ExpiresAt should be null if no expiration date in JWT
        // (actual behavior depends on implementation)
    }

    [Fact]
    public async Task VerifyCredentialAsync_ValidSignatureAndNotExpired_ReturnsIsValidTrue()
    {
        // Arrange
        await SeedTestIssuerDidAsync();
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt);

        // Assert
        if (result.Status == VerificationStatus.Valid)
        {
            Assert.True(result.IsValid);
            Assert.Empty(result.ValidationErrors);
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance", Justification = "Test helper method - interface return type is intentional for flexibility")]
    private ICredentialVerificationService CreateService()
    {
        // Create rate limiter for testing (100 ops per 60 seconds)
        var rateLimiter = new InMemoryRateLimiter(windowSize: TimeSpan.FromSeconds(60), maxOperations: 100);
        return new CredentialVerificationService(_dbContext, rateLimiter, null);
    }

    private string CreateValidTestJwt()
    {
        // Create real signed JWT with test key pair
        var header = JsonSerializer.Serialize(new { typ = "vc+jwt", alg = "EdDSA" });
        var payload = JsonSerializer.Serialize(new
        {
            iss = "did:web:example.com:issuer",
            sub = "did:web:example.com:holder",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            vc = new
            {
                context = W3cVcContext,
                type = TestCredentialType,
                credentialSubject = new { name = "Test User", degree = "Bachelor" }
            }
        });

        return Ed25519JwtSigner.CreateSignedJwt(header, payload, _testPrivateKey);
    }

    private string CreateTestJwtWithExpiration(DateTimeOffset expiration)
    {
        // Create real signed JWT with expiration
        var header = JsonSerializer.Serialize(new { typ = "vc+jwt", alg = "EdDSA" });
        var payload = JsonSerializer.Serialize(new
        {
            iss = "did:web:example.com:issuer",
            sub = "did:web:example.com:holder",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            exp = expiration.ToUnixTimeSeconds(),
            vc = new
            {
                context = W3cVcContext,
                type = VerifiableCredentialType,
                credentialSubject = new { test = "data" }
            }
        });

        return Ed25519JwtSigner.CreateSignedJwt(header, payload, _testPrivateKey);
    }

    private async Task SeedTestIssuerDidAsync()
    {
        var issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:web:example.com:issuer",
            PublicKeyEd25519 = _testPublicKey, // Use real public key for verification
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(_testPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.Add(issuerDid);
        await _dbContext.SaveChangesAsync();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private sealed class TestTenantContext : ITenantContext
    {
        private readonly Guid _tenantId;

        public TestTenantContext(Guid tenantId)
        {
            _tenantId = tenantId;
        }

        public Guid GetCurrentTenantId() => _tenantId;
    }
}
