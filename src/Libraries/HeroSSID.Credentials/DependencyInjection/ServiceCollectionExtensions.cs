using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

        // Full disclosure only: original issuer JWT plus a challenge-bound holder proof.
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IPresentationChallengeStore, InMemoryPresentationChallengeStore>();
        services.AddScoped<IVerifiablePresentationService, VerifiablePresentationService>();

        // Register credential revocation service (placeholder - throws NotImplementedException)
        services.AddScoped<ICredentialRevocationService, CredentialRevocationService>();

        return services;
    }
}
