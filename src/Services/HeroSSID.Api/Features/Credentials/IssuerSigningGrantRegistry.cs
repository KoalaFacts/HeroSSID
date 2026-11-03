using System.Globalization;
using System.Security.Claims;
using HeroSSID.Credentials.CredentialVerification;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Immutable, operator-provisioned per-tenant, per-OAuth-client, exact issuer
/// DID signing grants. Unconfigured tenants retain the legacy tenant-level
/// credential:issue policy; explicitly enforced tenants fail closed.
/// </summary>
internal sealed class IssuerSigningGrantRegistry
{
    private static readonly HashSet<string> AllowedGrantFields =
        new(StringComparer.OrdinalIgnoreCase) { "TenantId", "ClientId", "IssuerDid", "CredentialTypes" };

    private readonly HashSet<Guid> _enforcedTenants = [];
    private readonly Dictionary<(Guid Tenant, string ClientId, string IssuerDid), HashSet<string>?> _grants = [];

    public IssuerSigningGrantRegistry(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        IConfigurationSection root = configuration.GetSection("IssuerSigningGrants");
        if (root.Value is not null ||
            root.GetChildren().Any(static field =>
                field.Key is not ("EnforcedTenants" or "Grants")))
        {
            throw new InvalidOperationException("Invalid operator-owned issuer signing grant configuration.");
        }

        IConfigurationSection enforced = root.GetSection("EnforcedTenants");
        IConfigurationSection grants = root.GetSection("Grants");
        if (enforced.Value is not null || grants.Value is not null)
        {
            throw new InvalidOperationException("Invalid issuer signing grant structure.");
        }

        IConfigurationSection[] tenants = [.. enforced.GetChildren()];
        IConfigurationSection[] entries = [.. grants.GetChildren()];
        if (tenants.Length > 128 || entries.Length > 512)
        {
            throw new InvalidOperationException("Issuer signing grant configuration exceeds capacity.");
        }

        foreach (IConfigurationSection entry in tenants)
        {
            if (entry.GetChildren().Any() || !Guid.TryParse(entry.Value, out Guid tenant) ||
                tenant == Guid.Empty || !_enforcedTenants.Add(tenant))
            {
                throw new InvalidOperationException("Invalid or duplicate enforced issuer tenant.");
            }
        }

        foreach (IConfigurationSection entry in entries)
        {
            if (entry.Value is not null)
            {
                throw new InvalidOperationException("Invalid issuer grant entry.");
            }

            IConfigurationSection[] fields = [.. entry.GetChildren()];
            if (fields.Length is not (3 or 4) || fields.Any(field =>
                    !AllowedGrantFields.Contains(field.Key) ||
                    (string.Equals(field.Key, "CredentialTypes", StringComparison.OrdinalIgnoreCase)
                        ? field.Value is not null
                        : field.Value is null || field.GetChildren().Any())))
            {
                throw new InvalidOperationException("Unknown or missing issuer grant field.");
            }

            // Exact attestation types are an additional, independently enrolled
            // policy: a key-use grant alone does not authorize every statement.
            IConfigurationSection? configuredTypes = fields.FirstOrDefault(field =>
                string.Equals(field.Key, "CredentialTypes", StringComparison.OrdinalIgnoreCase));
            HashSet<string>? permittedTypes = null;
            if (configuredTypes is not null)
            {
                IConfigurationSection[] values = [.. configuredTypes.GetChildren()];
                if (values.Length is 0 or > 16)
                {
                    throw new InvalidOperationException("Invalid issuer credential type grant capacity.");
                }

                permittedTypes = new HashSet<string>(StringComparer.Ordinal);
                for (int index = 0; index < values.Length; index++)
                {
                    IConfigurationSection value = values[index];
                    string? type = value.Value;
                    if (!string.Equals(value.Key, index.ToString(CultureInfo.InvariantCulture),
                            StringComparison.Ordinal) ||
                        value.GetChildren().Any() ||
                        type is not { Length: > 0 and <= 128 } ||
                        type.Any(char.IsWhiteSpace) || type.Any(char.IsControl) ||
                        !permittedTypes.Add(type))
                    {
                        throw new InvalidOperationException("Invalid or duplicate issuer credential type grant.");
                    }
                }
            }

            string? client = entry["ClientId"];
            string? issuer = entry["IssuerDid"];
            if (!Guid.TryParse(entry["TenantId"], out Guid tenant) ||
                !_enforcedTenants.Contains(tenant) ||
                client is not { Length: > 0 and <= 128 } ||
                client.Any(char.IsWhiteSpace) || client.Any(char.IsControl) ||
                issuer is not { Length: > 0 and <= 255 } ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuer, out _) ||
                !_grants.TryAdd((tenant, client, issuer), permittedTypes))
            {
                throw new InvalidOperationException("Invalid, orphaned or duplicate issuer signing grant.");
            }
        }
    }

    // Callers without a credential type cannot bypass an opt-in type policy.
    internal bool IsAllowed(Guid tenant, ClaimsPrincipal principal, string? issuerDid) =>
        IsAllowed(tenant, principal, issuerDid, null);

    internal bool IsAllowed(Guid tenant, ClaimsPrincipal principal, string? issuerDid,
        string? credentialType)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (!_enforcedTenants.Contains(tenant))
        {
            return true;
        }

        if (principal.Identity?.IsAuthenticated != true || string.IsNullOrEmpty(issuerDid))
        {
            return false;
        }

        Claim[] clients = [.. principal.FindAll("client_id")];
        Claim[] subjects = [.. principal.FindAll("sub")];
        Claim[] tenants = [.. principal.FindAll("tenant_id")];
        return clients.Length == 1 && subjects.Length == 1 && tenants.Length == 1 &&
            Guid.TryParse(tenants[0].Value, out Guid signedTenant) && signedTenant == tenant &&
            string.Equals(clients[0].Value, subjects[0].Value, StringComparison.Ordinal) &&
            _grants.TryGetValue((tenant, clients[0].Value, issuerDid), out HashSet<string>? allowedTypes) &&
            (allowedTypes is null ||
                (credentialType is not null && allowedTypes.Contains(credentialType)));
    }
}
