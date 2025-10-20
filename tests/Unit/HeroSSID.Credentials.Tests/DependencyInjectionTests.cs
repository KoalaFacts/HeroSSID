using HeroSSID.Credentials.DependencyInjection;
using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Services;
using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Services;
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
    public void AddCredentialsServices_RegistersICredentialIssuanceService()
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
    public void AddCredentialsServices_WithNullServices_ThrowsArgumentNullException()
    {
        // Arrange
        ServiceCollection? services = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            services!.AddCredentialsServices());

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void AddCredentialsServices_ReturnsSameServiceCollection()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var result = services.AddCredentialsServices();

        // Assert
        Assert.Same(services, result);
    }
}
