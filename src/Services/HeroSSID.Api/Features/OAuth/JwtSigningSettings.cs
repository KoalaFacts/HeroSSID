using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace HeroSSID.Api.Features.OAuth;

/// <summary>
/// Validated access-token signing configuration, shared by JWT issuance and verification.
/// </summary>
internal sealed class JwtSigningSettings
{
    internal JwtSigningSettings(string secret, string issuer, string audience)
    {
        Secret = secret;
        Issuer = issuer;
        Audience = audience;
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    }

    internal SymmetricSecurityKey SigningKey { get; }
    internal string Secret { get; }
    internal string Issuer { get; }
    internal string Audience { get; }

    // Historical example retained only to detect and reject unsafe configuration.
    internal const string DevelopmentSecret = "your-256-bit-secret-key-change-in-production-min-32-chars";

    internal static JwtSigningSettings FromConfiguration(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var secret = configuration["Jwt:Secret"];
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException("Jwt:Secret must be explicitly configured in every environment.");
        }

        // HMAC zero-pads keys shorter than SHA-256's 64-byte block size. Appending
        // NUL bytes to the public development key does not change its HMAC signature.
        // Reject NULs rather than treating those equivalent encodings as distinct keys.
        if (secret.Contains('\0', StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Jwt:Secret must not contain NUL characters.");
        }

        if (secret.Contains("change-in-production", StringComparison.OrdinalIgnoreCase) ||
            secret.Contains("your-256-bit-secret", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Jwt:Secret must not use an example signing secret in any environment.");
        }

        if (Encoding.UTF8.GetByteCount(secret) < 32)
        {
            throw new InvalidOperationException("Jwt:Secret must contain at least 32 UTF-8 bytes.");
        }

        var issuer = RequireSetting(configuration, environment, "Jwt:Issuer", "https://herossid.api");
        var audience = RequireSetting(configuration, environment, "Jwt:Audience", "https://herossid.api");

        return new JwtSigningSettings(secret, issuer, audience);
    }

    private static string RequireSetting(
        IConfiguration configuration,
        IHostEnvironment environment,
        string name,
        string developmentDefault)
    {
        var value = configuration[name];
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        if (value is null && environment.IsDevelopment())
        {
            return developmentDefault;
        }

        throw new InvalidOperationException($"{name} must be non-empty and must be explicitly configured outside Development.");
    }
}
