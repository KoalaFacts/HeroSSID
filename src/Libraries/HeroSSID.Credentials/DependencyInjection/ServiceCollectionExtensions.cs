using HeroSSID.Credentials.Interfaces;
using HeroSSID.Credentials.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Credentials.DependencyInjection;

/// <summary>
/// Extension methods for registering credentials services with dependency injection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds W3C Verifiable Credentials services to the service collection
    /// </summary>
    /// <param name="services">The service collection to add services to</param>
    /// <returns>The service collection for method chaining</returns>
    public static IServiceCollection AddCredentialsServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Register credential issuance service
        services.AddScoped<ICredentialIssuanceService, CredentialIssuanceService>();

        // Register credential verification service
        services.AddScoped<ICredentialVerificationService, CredentialVerificationService>();

        return services;
    }
}
