using HeroSSID.Core.DidMethod;
using HeroSSID.Core.KeyEncryption;
using HeroSSID.Core.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.MvpImplementations;
using HeroSSID.Credentials.SdJwt;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.DidOperations.DidSigning;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Integration tests for Verifiable Presentation end-to-end flow
/// Tests the complete workflow: DID creation → Credential issuance → Presentation creation → Verification
/// </summary>
public sealed class VerifiablePresentationIntegrationTests : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture;
    private static readonly IDidMethod[] s_didMethods = [new DidKeyMethod()];
    private static readonly string[] s_employeeClaimsToDisclose = ["employeeName", "position"];
    private static readonly string[] s_degreeClaimsToDisclose = ["name", "degree"];

    public VerifiablePresentationIntegrationTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task CompleteVpFlowIssueCredentialCreatePresentationVerifySucceeds()
    {
        // Arrange - Setup database and services
        DbContextOptions<HeroDbContext> dbOptions = new DbContextOptionsBuilder<HeroDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .Options;

        await using var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Setup Data Protection for key encryption
        using var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var tenantId = Guid.NewGuid();
        var tenantContext = new TestTenantContext(tenantId);

        // Create logger factory for services that require it
        using var loggerFactory = LoggerFactory.Create(builder => { });
        var didCreationLogger = loggerFactory.CreateLogger<DidCreationService>();
        var vpLogger = loggerFactory.CreateLogger<VerifiablePresentationService>();

        var didMethodResolver = new DidMethodResolver(s_didMethods);
        var didCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            tenantContext,
            didMethodResolver,
            didCreationLogger,
            rateLimiter);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();

        var vpService = new VerifiablePresentationService(
            dbContext,
            sdJwtGenerator,
            sdJwtVerifier,
            rateLimiter,
            keyEncryptionService,
            vpLogger);

        // Act - Complete VP Flow

        // Step 1: Create issuer DID
        var issuerDidResult = await didCreationService.CreateDidAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Step 2: Create holder DID
        var holderDidResult = await didCreationService.CreateDidAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Step 3: Issue credential
        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDidResult.Id,
            holderDidResult.Id,
            "UniversityDegreeCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "name", "Alice Johnson" },
                { "degree", "Bachelor of Science" },
                { "university", "MIT" },
                { "graduationYear", 2024 }
            },
            expirationDate: DateTimeOffset.UtcNow.AddYears(5),
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Step 4: Create VP with selective disclosure (only name and degree)
        var presentationResult = await vpService.CreatePresentationAsync(
            tenantContext,
            credentialJwt,
            claimsToDisclose: s_degreeClaimsToDisclose,
            holderDidResult.Id,
            audience: "did:hero:verifier789",
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Step 5: Verify the presentation
        var verificationResult = await vpService.VerifyPresentationAsync(
            tenantContext,
            presentationResult.PresentationJwt,
            presentationResult.SelectedDisclosures,
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Assert - Verify all steps succeeded
        Assert.NotNull(issuerDidResult);
        Assert.NotNull(holderDidResult);
        Assert.NotEmpty(credentialJwt);
        Assert.NotNull(presentationResult);
        Assert.NotEmpty(presentationResult.PresentationJwt);
        Assert.NotEmpty(presentationResult.SelectedDisclosures);

        // Verify presentation is valid
        Assert.True(verificationResult.IsValid);
        Assert.Equal(PresentationVerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);

        // Verify disclosed claims match selection
        Assert.Contains("name", presentationResult.DisclosedClaimNames);
        Assert.Contains("degree", presentationResult.DisclosedClaimNames);
        Assert.Equal(2, presentationResult.DisclosedClaimNames.Length);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    [Fact]
    public async Task CrossTenantVpFlowIssuerAndHolderDifferentTenantsSucceeds()
    {
        // Arrange - Setup database and services
        DbContextOptions<HeroDbContext> dbOptions = new DbContextOptionsBuilder<HeroDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .Options;

        await using var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        using var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var issuerTenantId = Guid.NewGuid();
        var holderTenantId = Guid.NewGuid(); // Different tenant
        var issuerContext = new TestTenantContext(issuerTenantId);
        var holderContext = new TestTenantContext(holderTenantId);

        // Create logger factory for services that require it
        using var loggerFactory = LoggerFactory.Create(builder => { });
        var didCreationLogger = loggerFactory.CreateLogger<DidCreationService>();
        var vpLogger = loggerFactory.CreateLogger<VerifiablePresentationService>();

        var didMethodResolver = new DidMethodResolver(s_didMethods);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();

        var vpService = new VerifiablePresentationService(
            dbContext,
            sdJwtGenerator,
            sdJwtVerifier,
            rateLimiter,
            keyEncryptionService,
            vpLogger);

        // Create separate service instances for each tenant context
        var issuerDidCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            issuerContext,
            didMethodResolver,
            didCreationLogger,
            rateLimiter);

        var holderDidCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            holderContext,
            didMethodResolver,
            didCreationLogger,
            rateLimiter);

        // Act - Cross-tenant credential issuance

        // Issuer creates their DID
        var issuerDidResult = await issuerDidCreationService.CreateDidAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Holder creates their DID (different tenant)
        var holderDidResult = await holderDidCreationService.CreateDidAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Issuer issues credential to holder (cross-tenant)
        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            issuerContext,
            issuerDidResult.Id,
            holderDidResult.Id,
            "EmploymentCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "employeeName", "Bob Smith" },
                { "position", "Senior Developer" },
                { "department", "Engineering" }
            },
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Holder creates presentation with their tenant context
        var presentationResult = await vpService.CreatePresentationAsync(
            holderContext,
            credentialJwt,
            claimsToDisclose: s_employeeClaimsToDisclose,
            holderDidResult.Id,
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Assert
        Assert.NotEmpty(credentialJwt);
        Assert.NotNull(presentationResult);
        Assert.True(presentationResult.PresentationJwt.Length > 0);

        // Verify credential was persisted under issuer's tenant
        var issuedCredential = await dbContext.VerifiableCredentials
            .Where(vc => vc.TenantId == issuerTenantId)
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        Assert.NotNull(issuedCredential);
        Assert.Equal(issuerDidResult.Id, issuedCredential.IssuerDidId);
        Assert.Equal(holderDidResult.Id, issuedCredential.HolderDidId);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    [Fact]
    public async Task VpWithAllClaimsDisclosedReturnsAllData()
    {
        // Arrange - Setup database and services
        DbContextOptions<HeroDbContext> dbOptions = new DbContextOptionsBuilder<HeroDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .Options;

        await using var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        using var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var tenantId = Guid.NewGuid();
        var tenantContext = new TestTenantContext(tenantId);

        // Create logger factory for services that require it
        using var loggerFactory = LoggerFactory.Create(builder => { });
        var didCreationLogger = loggerFactory.CreateLogger<DidCreationService>();
        var vpLogger = loggerFactory.CreateLogger<VerifiablePresentationService>();

        var didMethodResolver = new DidMethodResolver(s_didMethods);
        var didCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            tenantContext,
            didMethodResolver,
            didCreationLogger,
            rateLimiter);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var sdJwtGenerator = new MockSdJwtGenerator();
        var sdJwtVerifier = new MockSdJwtVerifier();

        var vpService = new VerifiablePresentationService(
            dbContext,
            sdJwtGenerator,
            sdJwtVerifier,
            rateLimiter,
            keyEncryptionService,
            vpLogger);

        var issuerDidResult = await didCreationService.CreateDidAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        var holderDidResult = await didCreationService.CreateDidAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDidResult.Id,
            holderDidResult.Id,
            "TestCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "field1", "value1" },
                { "field2", "value2" },
                { "field3", "value3" }
            },
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Act - Disclose all claims (null means all)
        var presentationResult = await vpService.CreatePresentationAsync(
            tenantContext,
            credentialJwt,
            claimsToDisclose: null, // null = disclose all
            holderDidResult.Id,
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

        // Assert
        Assert.NotNull(presentationResult);
        Assert.Equal(3, presentationResult.DisclosedClaimNames.Length);
        Assert.Contains("field1", presentationResult.DisclosedClaimNames);
        Assert.Contains("field2", presentationResult.DisclosedClaimNames);
        Assert.Contains("field3", presentationResult.DisclosedClaimNames);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private sealed class TestTenantContext : ITenantContext
    {
        private readonly Guid _tenantId;
        public TestTenantContext(Guid tenantId) => _tenantId = tenantId;
        public Guid GetCurrentTenantId() => _tenantId;
    }
}
