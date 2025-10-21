using HeroSSID.Core.KeyEncryption;
using HeroSSID.Core.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.MvpImplementations;
using HeroSSID.Credentials.SdJwt;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// TDD tests for IVerifiablePresentationService - T034-T043
/// Tests Verifiable Presentations with selective disclosure (SD-JWT)
/// </summary>
public sealed class VerifiablePresentationServiceTests : IDisposable
{
    private static readonly string[] NameClaimArray = new[] { "name" };
    private static readonly string[] NameAndDegreeClaimArray = new[] { "name", "degree" };
    private static readonly string[] W3cContextArray = new[] { "https://www.w3.org/2018/credentials/v1" };
    private static readonly string[] CredentialTypeArray = new[] { "VerifiableCredential", "UniversityDegreeCredential" };

    private readonly HeroDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly Guid _tenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private readonly byte[] _testPrivateKey;
    private readonly byte[] _testPublicKey;
    private readonly InMemoryRateLimiter _rateLimiter;

    public VerifiablePresentationServiceTests()
    {
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
        var rawPrivateKey = key.Export(KeyBlobFormat.RawPrivateKey); // 64 bytes
        _testPrivateKey = rawPrivateKey[..32]; // Extract seed (first 32 bytes) for Ed25519JwtSigner
        _testPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    // T034: Constructor tests
    [Fact]
    public void ConstructorValidDependenciesCreatesService()
    {
        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();
        using var rateLimiter = new InMemoryRateLimiter();
        var keyEncryptionService = new MockKeyEncryptionService();

        var service = new VerifiablePresentationService(
            _dbContext,
            sdJwtGenerator,
            sdJwtVerifier,
            rateLimiter,
            keyEncryptionService);

        Assert.NotNull(service);
    }

    [Fact]
    public void ConstructorNullDbContextThrowsArgumentNullException()
    {
        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();
        using var rateLimiter = new InMemoryRateLimiter();
        var keyEncryptionService = new MockKeyEncryptionService();

        Assert.Throws<ArgumentNullException>(() =>
            new VerifiablePresentationService(null!, sdJwtGenerator, sdJwtVerifier, rateLimiter, keyEncryptionService));
    }

    // T036-T037: CreatePresentationAsync tests
    [Fact]
    public async Task CreatePresentationAsyncValidCredentialReturnsPresentation()
    {
        // Arrange
        await SeedTestDataAsync().ConfigureAwait(true);
        var service = CreateService();
        var credentialJwt = CreateValidTestCredentialJwt();

        var holderDid = await _dbContext.Dids.FirstAsync(d => d.TenantId == _tenantId).ConfigureAwait(true);

        // Act
        var result = await service.CreatePresentationAsync(
            _tenantContext,
            credentialJwt,
            claimsToDisclose: NameAndDegreeClaimArray,
            holderDid.Id).ConfigureAwait(true);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.PresentationJwt);
        Assert.NotNull(result.SelectedDisclosures);
        Assert.NotNull(result.DisclosedClaimNames);
    }

    [Fact]
    public async Task CreatePresentationAsyncNullCredentialJwtThrowsArgumentException()
    {
        var service = CreateService();
        var holderDidId = Guid.NewGuid();

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.CreatePresentationAsync(_tenantContext, null!, null, holderDidId).ConfigureAwait(true)).ConfigureAwait(true);
    }

    // T038-T039: VerifyPresentationAsync tests
    [Fact]
    public async Task VerifyPresentationAsyncValidPresentationReturnsValidResult()
    {
        // Arrange
        await SeedTestDataAsync().ConfigureAwait(true);
        var service = CreateService();
        var credentialJwt = CreateValidTestCredentialJwt();
        var holderDid = await _dbContext.Dids.FirstAsync(d => d.TenantId == _tenantId).ConfigureAwait(true);

        var presentation = await service.CreatePresentationAsync(
            _tenantContext,
            credentialJwt,
            claimsToDisclose: NameClaimArray,
            holderDid.Id).ConfigureAwait(true);

        // Act
        var result = await service.VerifyPresentationAsync(
            _tenantContext,
            presentation.PresentationJwt,
            presentation.SelectedDisclosures).ConfigureAwait(true);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsValid);
        Assert.Equal(PresentationVerificationStatus.Valid, result.Status);
    }

    [Fact]
    public async Task VerifyPresentationAsyncNullPresentationJwtThrowsArgumentException()
    {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyPresentationAsync(_tenantContext, null!, Array.Empty<string>()).ConfigureAwait(true)).ConfigureAwait(true);
    }

    // T040-T041: Selective disclosure tests
    [Fact]
    public async Task CreatePresentationAsyncSelectiveClaimsOnlyIncludesSelectedClaims()
    {
        // Arrange
        await SeedTestDataAsync().ConfigureAwait(true);
        var service = CreateService();
        var credentialJwt = CreateValidTestCredentialJwt();
        var holderDid = await _dbContext.Dids.FirstAsync(d => d.TenantId == _tenantId).ConfigureAwait(true);

        // Act - Only disclose "name", not "degree" or "gpa"
        var result = await service.CreatePresentationAsync(
            _tenantContext,
            credentialJwt,
            claimsToDisclose: NameClaimArray,
            holderDid.Id).ConfigureAwait(true);

        // Assert
        Assert.Contains("name", result.DisclosedClaimNames);
        Assert.Single(result.DisclosedClaimNames);
    }

    private VerifiablePresentationService CreateService()
    {
        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();
        var keyEncryptionService = new MockKeyEncryptionService();

        return new VerifiablePresentationService(
            _dbContext,
            sdJwtGenerator,
            sdJwtVerifier,
            _rateLimiter,
            keyEncryptionService);
    }

    private string CreateValidTestCredentialJwt()
    {
        var header = System.Text.Json.JsonSerializer.Serialize(new { typ = "vc+jwt", alg = "EdDSA" });
        var payload = System.Text.Json.JsonSerializer.Serialize(new
        {
            iss = "did:web:university.edu:issuer",
            sub = "did:web:student.example.com:holder",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            vc = new
            {
                context = W3cContextArray,
                type = CredentialTypeArray,
                credentialSubject = new { name = "Alice", degree = "BSc", gpa = 3.85 }
            }
        });

        return Utilities.Ed25519JwtSigner.CreateSignedJwt(header, payload, _testPrivateKey);
    }

    private async Task SeedTestDataAsync()
    {
        var holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:web:student.example.com:holder",
            PublicKeyEd25519 = _testPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(_testPublicKey),
            PrivateKeyEd25519Encrypted = _testPrivateKey, // MOCK: For testing, store actual private key
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        var issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            DidIdentifier = "did:web:university.edu:issuer",
            PublicKeyEd25519 = _testPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(_testPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = "{}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.AddRange(holderDid, issuerDid);
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        _rateLimiter.Dispose();
    }

    private sealed class TestTenantContext : ITenantContext
    {
        private readonly Guid _tenantId;
        public TestTenantContext(Guid tenantId) => _tenantId = tenantId;
        public Guid GetCurrentTenantId() => _tenantId;
    }

    private sealed class MockKeyEncryptionService : IKeyEncryptionService
    {
        // Mock pass-through encryption (for testing only)
        public byte[] Encrypt(byte[] plaintext) => plaintext;
        public byte[] Decrypt(byte[] ciphertext) => ciphertext;
        public string EncryptString(string plaintext) => plaintext;
        public string DecryptString(string ciphertext) => ciphertext;
    }
}
