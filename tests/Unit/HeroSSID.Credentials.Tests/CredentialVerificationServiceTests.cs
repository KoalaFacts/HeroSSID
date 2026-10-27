using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.MvpImplementations;
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
    private static readonly string[] TestCredentialType = new[] { "VerifiableCredential", "TestCredential" };

    private readonly HeroDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly Guid _tenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private readonly byte[] _testPrivateKey;
    private readonly byte[] _testPublicKey;
    private readonly InMemoryRateLimiter _rateLimiter;

    public CredentialVerificationServiceTests()
    {
        // Arrange: In-memory database for testing
        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new HeroDbContext(options);
        _tenantContext = new TestTenantContext(_tenantId);
        _rateLimiter = new InMemoryRateLimiter(
            windowSize: TimeSpan.FromSeconds(60),
            maxOperations: 100);

        // Generate test Ed25519 key pair
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(algorithm, keyParams);
        _testPrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        _testPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    [Fact]
    public async Task VerifyCredentialAsyncValidJwtVcReturnsVerificationResult()
    {
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var result = await CreateService().VerifyCredentialAsync(
            _tenantContext, CreateValidTestJwt()).ConfigureAwait(true);

        Assert.True(result.IsValid);
        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Empty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsyncInvalidSignatureReturnsFailedResult()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();

        // Create a valid JWT and tamper with it
        var validJwt = CreateValidTestJwt();
        var parts = validJwt.Split('.');
        var tamperedJwt = $"{parts[0]}.{parts[1]}.TAMPERED_SIGNATURE_XXX";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,tamperedJwt).ConfigureAwait(true);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.SignatureInvalid, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsyncExpiredCredentialReturnsFailedResult()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        // Create JWT with expiration date in the past
        var expiredJwt = CreateTestJwtWithExpiration(DateTimeOffset.UtcNow.AddYears(-1));

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,expiredJwt).ConfigureAwait(true);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.Expired, result.Status);
        Assert.Contains("expired", result.ValidationErrors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyCredentialAsyncMalformedJwtReturnsFailedResult()
    {
        // Arrange
        var service = CreateService();
        var malformedJwt = "not.a.valid.jwt.format";

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,malformedJwt).ConfigureAwait(true);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.MalformedJwt, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsyncNullCredentialJwtThrowsArgumentException()
    {
        // Arrange
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyCredentialAsync(_tenantContext,null!).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task VerifyCredentialAsyncEmptyCredentialJwtThrowsArgumentException()
    {
        // Arrange
        var service = CreateService();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyCredentialAsync(_tenantContext,string.Empty).ConfigureAwait(true)).ConfigureAwait(true);
    }

    [Fact]
    public async Task VerifyCredentialAsyncIssuerNotFoundReturnsFailedResult()
    {
        // Arrange
        var service = CreateService();
        // Valid JWT format but issuer DID doesn't exist in database
        var jwtWithUnknownIssuer = Ed25519JwtSigner.CreateSignedJwt(
            JsonSerializer.Serialize(new { typ = "vc+jwt", alg = "EdDSA" }),
            JsonSerializer.Serialize(new
            {
                iss = "did:web:example.com:unknown",
                sub = "did:web:example.com:holder",
                iat = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
                vc = new { type = TestCredentialType, credentialSubject = new { name = "Test User" } }
            }),
            _testPrivateKey);

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithUnknownIssuer).ConfigureAwait(true);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.IssuerNotFound, result.Status);
        Assert.Contains("issuer", result.ValidationErrors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyCredentialAsyncValidCredentialParsesCredentialSubject()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt).ConfigureAwait(true);

        // Assert
        Assert.True(result.IsValid);
        Assert.IsType<Dictionary<string, object>>(result.CredentialSubject);
        Assert.Equal("Test User", Assert.IsType<JsonElement>(result.CredentialSubject["name"]).GetString());
    }

    [Fact]
    public async Task VerifyCredentialAsyncValidCredentialExtractsIssuerDid()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt).ConfigureAwait(true);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal("did:web:example.com:issuer", result.IssuerDid);
    }

    [Fact]
    public async Task VerifyCredentialAsyncValidCredentialExtractsExpirationDate()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var jwtWithExpiration = CreateTestJwtWithExpiration(DateTimeOffset.UtcNow.AddYears(1));

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithExpiration).ConfigureAwait(true);

        // Assert
        Assert.True(result.IsValid);
        Assert.NotNull(result.ExpiresAt);
        Assert.True(result.ExpiresAt.Value > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task VerifyCredentialAsyncNoExpirationReturnsNullExpiresAt()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var jwtWithoutExpiration = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,jwtWithoutExpiration).ConfigureAwait(true);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Null(result.ExpiresAt);
    }

    [Fact]
    public async Task VerifyCredentialAsyncValidSignatureAndNotExpiredReturnsIsValidTrue()
    {
        // Arrange
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var validJwt = CreateValidTestJwt();

        // Act
        var result = await service.VerifyCredentialAsync(_tenantContext,validJwt).ConfigureAwait(true);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Empty(result.ValidationErrors);
    }

    [Fact]
    public async Task VerifyCredentialAsyncRevokedCredentialCannotBypassRevocationWithPaddedSignature()
    {
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var issuerDid = await _dbContext.Dids.SingleAsync().ConfigureAwait(true);
        var revokedJwt = CreateValidTestJwt();
        _dbContext.VerifiableCredentials.Add(new VerifiableCredentialEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            IssuerDidId = issuerDid.Id,
            HolderDidId = issuerDid.Id,
            CredentialType = "TestCredential",
            CredentialJwt = revokedJwt,
            Status = "revoked",
            IssuedAt = DateTimeOffset.UtcNow,
            RevokedAt = DateTimeOffset.UtcNow
        });
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);

        var service = CreateService();
        var revokedResult = await service.VerifyCredentialAsync(_tenantContext, revokedJwt).ConfigureAwait(true);
        Assert.False(revokedResult.IsValid);
        Assert.Equal(VerificationStatus.Revoked, revokedResult.Status);

        // The original verifier accepted the same signature bytes with padding,
        // but its database revocation check compared JWT text byte-for-byte.
        var paddedJwt = revokedJwt + "==";
        var paddedResult = await service.VerifyCredentialAsync(_tenantContext, paddedJwt).ConfigureAwait(true);
        Assert.False(paddedResult.IsValid);
        Assert.Equal(VerificationStatus.SignatureInvalid, paddedResult.Status);
    }

    [Fact]
    public async Task VerifyCredentialAsyncMalformedRequestsConsumeRateLimitPerTenant()
    {
        using var limiter = new InMemoryRateLimiter(windowSize: TimeSpan.FromMinutes(1), maxOperations: 2);
        var verifier = new CredentialVerificationService(_dbContext, limiter);
        const string invalidJwt = "not.a.valid.jwt.format";

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var rejected = await verifier.VerifyCredentialAsync(_tenantContext, invalidJwt).ConfigureAwait(true);
            Assert.False(rejected.IsValid);
            Assert.Equal(VerificationStatus.MalformedJwt, rejected.Status);
        }

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await verifier.VerifyCredentialAsync(_tenantContext, invalidJwt).ConfigureAwait(true)).ConfigureAwait(true);
        Assert.Contains("Rate limit exceeded", exception.Message, StringComparison.Ordinal);

        // The exhausted caller must not consume another tenant's independent window.
        var otherTenant = new TestTenantContext(Guid.Parse("22222222-2222-2222-2222-222222222222"));
        var otherResult = await verifier.VerifyCredentialAsync(otherTenant, invalidJwt).ConfigureAwait(true);
        Assert.Equal(VerificationStatus.MalformedJwt, otherResult.Status);
    }

    [Fact]
    public async Task VerifyCredentialAsyncSuccessfulRequestsAlsoConsumeRateLimit()
    {
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        using var limiter = new InMemoryRateLimiter(windowSize: TimeSpan.FromMinutes(1), maxOperations: 1);
        var verifier = new CredentialVerificationService(_dbContext, limiter);
        var credential = CreateValidTestJwt();

        var first = await verifier.VerifyCredentialAsync(_tenantContext, credential).ConfigureAwait(true);
        Assert.True(first.IsValid);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await verifier.VerifyCredentialAsync(_tenantContext, credential).ConfigureAwait(true)).ConfigureAwait(true);
        Assert.Contains("Rate limit exceeded", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyCredentialFromIssuerKeepsPublicLookupsInTheExplicitIssuerTenant()
    {
        await SeedTestIssuerDidAsync().ConfigureAwait(true);
        var service = CreateService();
        var original = CreateValidTestJwt();
        var requester = new TestTenantContext(Guid.Parse("22222222-2222-2222-2222-222222222222"));

        var tenantLocal = await service.VerifyCredentialAsync(requester, original).ConfigureAwait(true);
        Assert.Equal(VerificationStatus.IssuerNotFound, tenantLocal.Status);
        var publicProof = await service.VerifyCredentialFromIssuerAsync(requester, _tenantId, original).ConfigureAwait(true);
        Assert.True(publicProof.IsValid);
        var wrongLookup = await service.VerifyCredentialFromIssuerAsync(_tenantContext, requester.GetCurrentTenantId(), original).ConfigureAwait(true);
        Assert.Equal(VerificationStatus.IssuerNotFound, wrongLookup.Status);

        var issuer = await _dbContext.Dids.SingleAsync().ConfigureAwait(true);
        _dbContext.VerifiableCredentials.Add(new VerifiableCredentialEntity
        {
            Id = Guid.NewGuid(), TenantId = _tenantId, IssuerDidId = issuer.Id, HolderDidId = issuer.Id,
            CredentialType = "TestCredential", CredentialJwt = original, Status = "revoked"
        });
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);
        var revoked = await service.VerifyCredentialFromIssuerAsync(requester, _tenantId, original).ConfigureAwait(true);
        Assert.False(revoked.IsValid);
        Assert.Equal(VerificationStatus.Revoked, revoked.Status);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task VerifyCredentialFromIssuerRejectsEmptyTenantIdentities(bool emptyRequester, bool emptyIssuer)
    {
        var requester = new TestTenantContext(emptyRequester ? Guid.Empty : _tenantId);
        var issuer = emptyIssuer ? Guid.Empty : _tenantId;
        await Assert.ThrowsAsync<ArgumentException>(() => CreateService().VerifyCredentialFromIssuerAsync(
            requester, issuer, CreateValidTestJwt())).ConfigureAwait(true);
    }

    private CredentialVerificationService CreateService()
    {
        return new CredentialVerificationService(_dbContext, _rateLimiter, null);
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
                type = TestCredentialType,
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
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        _rateLimiter.Dispose();
    }

    private sealed class TestTenantContext(Guid tenantId) : ITenantContext
    {
        private readonly Guid _tenantId = tenantId;

        public Guid GetCurrentTenantId() => _tenantId;
    }
}
