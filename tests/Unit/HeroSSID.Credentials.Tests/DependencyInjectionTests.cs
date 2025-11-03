using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.DependencyInjection;
using HeroSSID.Credentials.SdJwt;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// T021: Integration tests for credential issuance service DI registration
/// </summary>
public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddCredentialsServicesRegistersICredentialIssuanceService()
    {
        // Arrange
        var services = new ServiceCollection();

        // Add dependencies that CredentialIssuanceService requires
        services.AddDbContext<HeroDbContext>(options =>
            options.UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()));

        // Add Data Protection (required by LocalKeyEncryptionService)
        services.AddDataProtection();

        services.AddScoped<IKeyEncryptionService, LocalKeyEncryptionService>();
        services.AddScoped<IRateLimiter, InMemoryRateLimiter>();

        // Act
        services.AddCredentialsServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var credentialIssuanceService = serviceProvider.GetService<ICredentialIssuanceService>();
        Assert.NotNull(credentialIssuanceService);
        Assert.IsType<CredentialIssuanceService>(credentialIssuanceService);
    }

    [Fact]
    public void AddCredentialsServicesWithNullServicesThrowsArgumentNullException()
    {
        // Arrange
        ServiceCollection? services = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            services!.AddCredentialsServices());

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void AddCredentialsServicesReturnsSameServiceCollection()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var result = services.AddCredentialsServices();

        // Assert
        Assert.Same(services, result);
    }
}
