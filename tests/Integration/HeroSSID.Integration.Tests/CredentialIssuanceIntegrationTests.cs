using HeroSSID.Core.KeyEncryption;
using HeroSSID.Core.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.MvpImplementations;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Integration tests for W3C Verifiable Credentials issuance and verification.
/// Tests the complete flow from DID creation through credential issuance to verification.
/// </summary>
#pragma warning disable CA1307 // string.Replace overload - test data generation only
#pragma warning disable CA1859 // Concrete types for performance - prefer interfaces for testability
#pragma warning disable CA2007 // ConfigureAwait - test methods don't need it
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1001 // Types that own disposable fields should be disposable - IAsyncLifetime handles disposal
#pragma warning disable CA5394 // Do not use insecure randomness - test data only
public sealed class CredentialIssuanceIntegrationTests : IAsyncLifetime
{
    private HeroDbContext? _dbContext;
    private ICredentialIssuanceService? _issuanceService;
    private ICredentialVerificationService? _verificationService;
    private IKeyEncryptionService? _keyEncryptionService;
    private IRateLimiter? _rateLimiter;
    private bool _disposed;

    public async ValueTask InitializeAsync()
    {
        // Setup in-memory database for testing
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"CredentialTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);

        // Setup services - create DataProtection provider for encryption
        var serviceProvider = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = serviceProvider.GetRequiredService<IDataProtectionProvider>();

        _keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        _rateLimiter = new InMemoryRateLimiter();

        _issuanceService = new CredentialIssuanceService(
            _dbContext,
            _keyEncryptionService,
            _rateLimiter);

        _verificationService = new CredentialVerificationService(
            _dbContext,
            _rateLimiter);
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
    public async Task IssueCredential_EndToEnd_SuccessfullyCreatesAndVerifiesJwtVc()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_issuanceService);
        Assert.NotNull(_verificationService);
        Assert.NotNull(_keyEncryptionService);

        // Create issuer DID (University)
        using Key issuerKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] issuerPublicKey = issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] issuerPrivateKey = issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] issuerEncryptedPrivateKey = _keyEncryptionService.Encrypt(issuerPrivateKey);

        string issuerDidIdentifier = $"did:key:z{Convert.ToBase64String(issuerPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = issuerDidIdentifier,
            PublicKeyEd25519 = issuerPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPublicKey),
            PrivateKeyEd25519Encrypted = issuerEncryptedPrivateKey,
            DidDocumentJson = $@"{{""id"":""{issuerDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Create holder DID (Student)
        using Key holderKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string holderDidIdentifier = $"did:key:z{Convert.ToBase64String(holderPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = holderDidIdentifier,
            PublicKeyEd25519 = holderPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64], // Not needed for holder in this test
            DidDocumentJson = $@"{{""id"":""{holderDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.AddRange(issuerDid, holderDid);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        // Prepare credential data
        var tenantContext = new DefaultTenantContext();
        var credentialSubject = new Dictionary<string, object>
        {
            { "degree", "Bachelor of Science in Computer Science" },
            { "graduationDate", "2025-05-15" },
            { "gpa", 3.85 }
        };

        // Act - Issue credential
        string jwtVc = await _issuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDid.Id,
            holderDid.Id,
            "UniversityDegreeCredential",
            credentialSubject,
            expirationDate: DateTimeOffset.UtcNow.AddYears(5),
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert - Verify JWT structure
        Assert.NotNull(jwtVc);
        Assert.NotEmpty(jwtVc);

        // JWT should have 3 parts (header.payload.signature)
        string[] jwtParts = jwtVc.Split('.');
        Assert.Equal(3, jwtParts.Length);

        // Verify credential was stored in database
        VerifiableCredentialEntity? storedCredential = await _dbContext.VerifiableCredentials
            .FirstOrDefaultAsync(c => c.CredentialJwt == jwtVc, TestContext.Current.CancellationToken);

        Assert.NotNull(storedCredential);
        Assert.Equal(HeroDbContext.DefaultTenantId, storedCredential.TenantId);
        Assert.Equal(issuerDid.Id, storedCredential.IssuerDidId);
        Assert.Equal(holderDid.Id, storedCredential.HolderDidId);
        Assert.Equal("UniversityDegreeCredential", storedCredential.CredentialType);
        Assert.Equal("active", storedCredential.Status);
        Assert.NotNull(storedCredential.ExpiresAt);

        // Act - Verify credential
        var verificationResult = await _verificationService.VerifyCredentialAsync(
            tenantContext,
            jwtVc,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert - Verification successful
        Assert.NotNull(verificationResult);
        Assert.True(verificationResult.IsValid, $"Verification failed: {string.Join(", ", verificationResult.ValidationErrors)}");
        Assert.Equal(VerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);
        Assert.Equal(issuerDidIdentifier, verificationResult.IssuerDid);
        Assert.NotNull(verificationResult.CredentialSubject);
        Assert.NotNull(verificationResult.ExpiresAt);

        // Clear sensitive data
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(issuerPrivateKey);
    }

    [Fact]
    public async Task IssueCredential_WithExpiration_VerificationDetectsExpiredCredential()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_issuanceService);
        Assert.NotNull(_verificationService);
        Assert.NotNull(_keyEncryptionService);

        // Create issuer DID
        using Key issuerKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] issuerPublicKey = issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] issuerPrivateKey = issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] issuerEncryptedPrivateKey = _keyEncryptionService.Encrypt(issuerPrivateKey);

        string issuerDidIdentifier = $"did:key:z{Convert.ToBase64String(issuerPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = issuerDidIdentifier,
            PublicKeyEd25519 = issuerPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPublicKey),
            PrivateKeyEd25519Encrypted = issuerEncryptedPrivateKey,
            DidDocumentJson = $@"{{""id"":""{issuerDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Create holder DID
        using Key holderKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string holderDidIdentifier = $"did:key:z{Convert.ToBase64String(holderPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = holderDidIdentifier,
            PublicKeyEd25519 = holderPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = $@"{{""id"":""{holderDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.AddRange(issuerDid, holderDid);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var tenantContext = new DefaultTenantContext();
        var credentialSubject = new Dictionary<string, object>
        {
            { "license", "Class A Driver's License" },
            { "expiryNote", "This credential expired in the past" }
        };

        // Act - Issue credential with past expiration date
        string jwtVc = await _issuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDid.Id,
            holderDid.Id,
            "DriverLicenseCredential",
            credentialSubject,
            expirationDate: DateTimeOffset.UtcNow.AddDays(-1), // Expired yesterday
            cancellationToken: TestContext.Current.CancellationToken);

        // Act - Verify expired credential
        var verificationResult = await _verificationService.VerifyCredentialAsync(
            tenantContext,
            jwtVc,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert - Verification detects expiration
        Assert.NotNull(verificationResult);
        Assert.False(verificationResult.IsValid);
        Assert.Equal(VerificationStatus.Expired, verificationResult.Status);
        Assert.NotEmpty(verificationResult.ValidationErrors);
        // Check that the validation error mentions "expired" in some form
        bool hasExpiredError = verificationResult.ValidationErrors.Any(e => e.Contains("expired", StringComparison.OrdinalIgnoreCase) || e.Contains("Expired", StringComparison.Ordinal));
        Assert.True(hasExpiredError, $"Expected 'expired' in validation errors but got: {string.Join(", ", verificationResult.ValidationErrors)}");

        // Clear sensitive data
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(issuerPrivateKey);
    }

    [Fact]
    public async Task IssueCredential_MultiTenantIsolation_PreventsUnauthorizedAccess()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_issuanceService);
        Assert.NotNull(_keyEncryptionService);

        Guid tenant1 = HeroDbContext.DefaultTenantId;
        Guid tenant2 = Guid.NewGuid();

        // Create issuer DID in Tenant 2 (NOT the default tenant)
        using Key issuerKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] issuerPublicKey = issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] issuerPrivateKey = issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] issuerEncryptedPrivateKey = _keyEncryptionService.Encrypt(issuerPrivateKey);

        DidEntity issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenant2, // Tenant 2 (NOT the default)
            DidIdentifier = $"did:key:tenant2issuer",
            PublicKeyEd25519 = issuerPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPublicKey),
            PrivateKeyEd25519Encrypted = issuerEncryptedPrivateKey,
            DidDocumentJson = @"{""id"":""did:key:tenant2issuer""}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Create holder DID in Tenant 1 (default tenant)
        using Key holderKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        DidEntity holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenant1, // Tenant 1 (default)
            DidIdentifier = $"did:key:tenant1holder",
            PublicKeyEd25519 = holderPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = @"{""id"":""did:key:tenant1holder""}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.AddRange(issuerDid, holderDid);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        // Act - Attempt to issue credential using DefaultTenantContext (Tenant 1) with Tenant 2's issuer DID
        // This should fail because the issuer DID belongs to Tenant 2, not Tenant 1
        var tenantContext = new DefaultTenantContext(); // Returns default tenant (Tenant 1)
        var credentialSubject = new Dictionary<string, object> { { "test", "value" } };

        // Assert - Should throw ArgumentException due to tenant isolation
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await _issuanceService.IssueCredentialAsync(
                tenantContext,
                issuerDid.Id, // Tenant 2 DID (should fail - not in Tenant 1)
                holderDid.Id, // Tenant 1 DID
                "TestCredential",
                credentialSubject,
                cancellationToken: TestContext.Current.CancellationToken);
        });

        // Verify the error message indicates tenant isolation
        Assert.Contains("tenant", exception.Message, StringComparison.OrdinalIgnoreCase);

        // Clear sensitive data
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(issuerPrivateKey);
    }

    [Fact]
    public async Task IssueCredential_MarkAsRevoked_VerificationReturnsRevoked()
    {
        // Arrange
        Assert.NotNull(_dbContext);
        Assert.NotNull(_issuanceService);
        Assert.NotNull(_verificationService);
        Assert.NotNull(_keyEncryptionService);

        // Create issuer DID
        using Key issuerKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] issuerPublicKey = issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] issuerPrivateKey = issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        byte[] issuerEncryptedPrivateKey = _keyEncryptionService.Encrypt(issuerPrivateKey);

        string issuerDidIdentifier = $"did:key:z{Convert.ToBase64String(issuerPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity issuerDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = issuerDidIdentifier,
            PublicKeyEd25519 = issuerPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(issuerPublicKey),
            PrivateKeyEd25519Encrypted = issuerEncryptedPrivateKey,
            DidDocumentJson = $@"{{""id"":""{issuerDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Create holder DID
        using Key holderKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string holderDidIdentifier = $"did:key:z{Convert.ToBase64String(holderPublicKey).Replace("+", "").Replace("/", "").Replace("=", "")}";

        DidEntity holderDid = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = holderDidIdentifier,
            PublicKeyEd25519 = holderPublicKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64],
            DidDocumentJson = $@"{{""id"":""{holderDidIdentifier}""}}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.Dids.AddRange(issuerDid, holderDid);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var tenantContext = new DefaultTenantContext();
        var credentialSubject = new Dictionary<string, object>
        {
            { "certificateId", "CERT-12345" },
            { "certificateName", "Security Clearance" }
        };

        // Act - Issue credential
        string jwtVc = await _issuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDid.Id,
            holderDid.Id,
            "SecurityClearanceCredential",
            credentialSubject,
            cancellationToken: TestContext.Current.CancellationToken);

        // Verify credential is initially valid
        var initialVerificationResult = await _verificationService.VerifyCredentialAsync(
            tenantContext,
            jwtVc,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(initialVerificationResult.IsValid);
        Assert.Equal(VerificationStatus.Valid, initialVerificationResult.Status);

        // Act - Mark credential as revoked in database
        VerifiableCredentialEntity? storedCredential = await _dbContext.VerifiableCredentials
            .FirstOrDefaultAsync(c => c.CredentialJwt == jwtVc, TestContext.Current.CancellationToken);

        Assert.NotNull(storedCredential);
        storedCredential.Status = "revoked";
        storedCredential.RevokedAt = DateTimeOffset.UtcNow;
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        // Act - Verify credential after revocation
        var revokedVerificationResult = await _verificationService.VerifyCredentialAsync(
            tenantContext,
            jwtVc,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert - Verification should detect revocation
        Assert.False(revokedVerificationResult.IsValid);
        Assert.Equal(VerificationStatus.Revoked, revokedVerificationResult.Status);
        Assert.NotEmpty(revokedVerificationResult.ValidationErrors);
        bool hasRevokedError = revokedVerificationResult.ValidationErrors.Any(e =>
            e.Contains("revoked", StringComparison.OrdinalIgnoreCase));
        Assert.True(hasRevokedError, $"Expected 'revoked' in validation errors but got: {string.Join(", ", revokedVerificationResult.ValidationErrors)}");

        // Clear sensitive data
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(issuerPrivateKey);
    }
}
#pragma warning restore CA5394
#pragma warning restore CA1001
#pragma warning restore CA1707
#pragma warning restore CA2007
#pragma warning restore CA1859
#pragma warning restore CA1307
