using System.Security.Claims;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Verifier-operator-owned issuance boundary. This test-first placeholder
/// intentionally fails until the per-client signing grant is implemented.
/// </summary>
internal sealed class IssuerSigningGrantRegistry
{
    internal IssuerSigningGrantRegistry(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
    }

    internal bool IsAllowed(Guid tenant, ClaimsPrincipal principal, string? issuerDid) =>
        throw new NotSupportedException("Issuer signing grant enforcement not implemented.");
}
