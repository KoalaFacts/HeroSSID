using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Services;
using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Services;
using HeroSSID.Data;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Services;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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

        var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync().ConfigureAwait(false);

        // Setup Data Protection for key encryption
        var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var didMethodResolver = new DidMethodResolver();
        var didCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            didMethodResolver,
            rateLimiter);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var vpService = new VerifiablePresentationService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var tenantId = Guid.NewGuid();
        var tenantContext = new TestTenantContext(tenantId);

        // Act - Complete VP Flow

        // Step 1: Create issuer DID
        var issuerDidResult = await didCreationService.CreateDidAsync(
            tenantContext,
            cancellationToken: default).ConfigureAwait(false);

        // Step 2: Create holder DID
        var holderDidResult = await didCreationService.CreateDidAsync(
            tenantContext,
            cancellationToken: default).ConfigureAwait(false);

        // Step 3: Issue credential
        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDidResult.DidId,
            holderDidResult.DidId,
            "UniversityDegreeCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "name", "Alice Johnson" },
                { "degree", "Bachelor of Science" },
                { "university", "MIT" },
                { "graduationYear", 2024 }
            },
            expirationDate: DateTimeOffset.UtcNow.AddYears(5),
            cancellationToken: default).ConfigureAwait(false);

        // Step 4: Create VP with selective disclosure (only name and degree)
        var presentationResult = await vpService.CreatePresentationAsync(
            tenantContext,
            credentialJwt,
            claimsToDisclose: new[] { "name", "degree" },
            holderDidResult.DidId,
            audience: "did:hero:verifier789",
            cancellationToken: default).ConfigureAwait(false);

        // Step 5: Verify the presentation
        var verificationResult = await vpService.VerifyPresentationAsync(
            tenantContext,
            presentationResult.PresentationJwt,
            presentationResult.SelectedDisclosures,
            cancellationToken: default).ConfigureAwait(false);

        // Assert - Verify all steps succeeded
        Assert.NotNull(issuerDidResult);
        Assert.NotNull(holderDidResult);
        Assert.NotEmpty(credentialJwt);
        Assert.NotNull(presentationResult);
        Assert.NotEmpty(presentationResult.PresentationJwt);
        Assert.NotEmpty(presentationResult.SelectedDisclosures);

        // Verify presentation is valid
        Assert.True(verificationResult.IsValid);
        Assert.Equal(HeroSSID.Credentials.Models.PresentationVerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);

        // Verify disclosed claims match selection
        Assert.Contains("name", presentationResult.DisclosedClaimNames);
        Assert.Contains("degree", presentationResult.DisclosedClaimNames);
        Assert.Equal(2, presentationResult.DisclosedClaimNames.Length);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync().ConfigureAwait(false);
    }

    [Fact]
    public async Task CrossTenantVpFlowIssuerAndHolderDifferentTenantsSucceeds()
    {
        // Arrange - Setup database and services
        DbContextOptions<HeroDbContext> dbOptions = new DbContextOptionsBuilder<HeroDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .Options;

        var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync().ConfigureAwait(false);

        var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var didMethodResolver = new DidMethodResolver();
        var didCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            didMethodResolver,
            rateLimiter);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var vpService = new VerifiablePresentationService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var issuerTenantId = Guid.NewGuid();
        var holderTenantId = Guid.NewGuid(); // Different tenant
        var issuerContext = new TestTenantContext(issuerTenantId);
        var holderContext = new TestTenantContext(holderTenantId);

        // Act - Cross-tenant credential issuance

        // Issuer creates their DID
        var issuerDidResult = await didCreationService.CreateDidAsync(
            issuerContext,
            cancellationToken: default).ConfigureAwait(false);

        // Holder creates their DID (different tenant)
        var holderDidResult = await didCreationService.CreateDidAsync(
            holderContext,
            cancellationToken: default).ConfigureAwait(false);

        // Issuer issues credential to holder (cross-tenant)
        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            issuerContext,
            issuerDidResult.DidId,
            holderDidResult.DidId,
            "EmploymentCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "employeeName", "Bob Smith" },
                { "position", "Senior Developer" },
                { "department", "Engineering" }
            },
            cancellationToken: default).ConfigureAwait(false);

        // Holder creates presentation with their tenant context
        var presentationResult = await vpService.CreatePresentationAsync(
            holderContext,
            credentialJwt,
            claimsToDisclose: new[] { "employeeName", "position" },
            holderDidResult.DidId,
            cancellationToken: default).ConfigureAwait(false);

        // Assert
        Assert.NotEmpty(credentialJwt);
        Assert.NotNull(presentationResult);
        Assert.True(presentationResult.PresentationJwt.Length > 0);

        // Verify credential was persisted under issuer's tenant
        var issuedCredential = await dbContext.VerifiableCredentials
            .Where(vc => vc.TenantId == issuerTenantId)
            .FirstOrDefaultAsync().ConfigureAwait(false);

        Assert.NotNull(issuedCredential);
        Assert.Equal(issuerDidResult.DidId, issuedCredential.IssuerDidId);
        Assert.Equal(holderDidResult.DidId, issuedCredential.HolderDidId);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync().ConfigureAwait(false);
    }

    [Fact]
    public async Task VpWithAllClaimsDisclosedReturnsAllData()
    {
        // Arrange - Setup database and services
        DbContextOptions<HeroDbContext> dbOptions = new DbContextOptionsBuilder<HeroDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .Options;

        var dbContext = new HeroDbContext(dbOptions);
        await dbContext.Database.EnsureCreatedAsync().ConfigureAwait(false);

        var services = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider();

        var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
        var keyEncryptionService = new LocalKeyEncryptionService(dataProtectionProvider);
        var rateLimiter = new InMemoryRateLimiter();

        var didMethodResolver = new DidMethodResolver();
        var didCreationService = new DidCreationService(
            dbContext,
            keyEncryptionService,
            didMethodResolver,
            rateLimiter);

        var credentialIssuanceService = new CredentialIssuanceService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var vpService = new VerifiablePresentationService(
            dbContext,
            keyEncryptionService,
            rateLimiter);

        var tenantId = Guid.NewGuid();
        var tenantContext = new TestTenantContext(tenantId);

        var issuerDidResult = await didCreationService.CreateDidAsync(tenantContext, cancellationToken: default).ConfigureAwait(false);
        var holderDidResult = await didCreationService.CreateDidAsync(tenantContext, cancellationToken: default).ConfigureAwait(false);

        var credentialJwt = await credentialIssuanceService.IssueCredentialAsync(
            tenantContext,
            issuerDidResult.DidId,
            holderDidResult.DidId,
            "TestCredential",
            new System.Collections.Generic.Dictionary<string, object>
            {
                { "field1", "value1" },
                { "field2", "value2" },
                { "field3", "value3" }
            },
            cancellationToken: default).ConfigureAwait(false);

        // Act - Disclose all claims (null means all)
        var presentationResult = await vpService.CreatePresentationAsync(
            tenantContext,
            credentialJwt,
            claimsToDisclose: null, // null = disclose all
            holderDidResult.DidId,
            cancellationToken: default).ConfigureAwait(false);

        // Assert
        Assert.NotNull(presentationResult);
        Assert.Equal(3, presentationResult.DisclosedClaimNames.Length);
        Assert.Contains("field1", presentationResult.DisclosedClaimNames);
        Assert.Contains("field2", presentationResult.DisclosedClaimNames);
        Assert.Contains("field3", presentationResult.DisclosedClaimNames);

        // Cleanup
        await dbContext.Database.EnsureDeletedAsync().ConfigureAwait(false);
    }

    private sealed class TestTenantContext : ITenantContext
    {
        private readonly Guid _tenantId;
        public TestTenantContext(Guid tenantId) => _tenantId = tenantId;
        public Guid GetCurrentTenantId() => _tenantId;
    }
}
