using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using HeroSSID.Core.TenantManagement;

namespace HeroSSID.Api.Authentication;

/// <summary>Tenant identity comes exclusively from a validated authenticated request.</summary>
internal sealed class AuthenticatedTenantContext(IHttpContextAccessor accessor) : ITenantContext
{
    public Guid GetCurrentTenantId() => TryGetTenantId(accessor.HttpContext?.User, out var tenantId)
        ? tenantId
        : throw new InvalidOperationException("A validated tenant identity is required.");

    // Called only after cryptographic token validation. Claim normalization can discard
    // duplicate JSON members or flatten a one-element array, so inspect the signed payload.
    internal static bool HasUnambiguousValidatedTenant(SecurityToken token, ClaimsPrincipal? principal)
    {
        var encodedPayload = token switch
        {
            JsonWebToken jsonToken => jsonToken.EncodedPayload,
            JwtSecurityToken jwtToken => jwtToken.RawPayload,
            _ => null
        };
        if (string.IsNullOrEmpty(encodedPayload)) { return false; }
        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(encodedPayload));
            if (payload.RootElement.ValueKind != JsonValueKind.Object) { return false; }
            var tenantMembers = payload.RootElement.EnumerateObject()
                .Where(property => property.NameEquals("tenant_id")).ToArray();
            return tenantMembers.Length == 1 && tenantMembers[0].Value.ValueKind == JsonValueKind.String &&
                Guid.TryParse(tenantMembers[0].Value.GetString(), out var rawTenantId) && rawTenantId != Guid.Empty &&
                TryGetTenantId(principal, out var principalTenantId) && rawTenantId == principalTenantId;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    internal static bool TryGetTenantId(ClaimsPrincipal? principal, out Guid tenantId)
    {
        tenantId = Guid.Empty;
        if (principal?.Identity?.IsAuthenticated != true) { return false; }
        var claims = principal.FindAll("tenant_id").ToArray();
        return claims.Length == 1 && Guid.TryParse(claims[0].Value, out tenantId) && tenantId != Guid.Empty;
    }
}
