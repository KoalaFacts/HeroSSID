using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace HeroSSID.Api.Authentication;

/// <summary>One immutable, validated configuration for issuing and validating access tokens.</summary>
internal sealed class JwtConfiguration
{
    public JwtConfiguration(IConfiguration configuration)
    {
        var secret = configuration["Jwt:Secret"];
        if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32 ||
            secret.Contains("change-in-production", StringComparison.OrdinalIgnoreCase) ||
            secret.Contains("your-256-bit-secret", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Jwt:Secret must be configured with a non-placeholder signing secret of at least 32 UTF-8 bytes.");
        }
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        Issuer = configuration["Jwt:Issuer"] ?? "https://herossid.api";
        Audience = configuration["Jwt:Audience"] ?? "https://herossid.api";
        if (string.IsNullOrWhiteSpace(Issuer) || string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException("Jwt:Issuer and Jwt:Audience must not be empty.");
        }
    }

    internal SymmetricSecurityKey SigningKey { get; }
    internal string Issuer { get; }
    internal string Audience { get; }
}
