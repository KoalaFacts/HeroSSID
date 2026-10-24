using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

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
    }

    internal string Secret { get; }
    internal string Issuer { get; }
    internal string Audience { get; }

    // Local development convenience only. A production deployment must never accept this key.
    internal const string DevelopmentSecret = "your-256-bit-secret-key-change-in-production-min-32-chars";

    internal static JwtSigningSettings FromConfiguration(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var secret = configuration["Jwt:Secret"];
        if (string.IsNullOrWhiteSpace(secret))
        {
            if (!environment.IsDevelopment())
            {
                throw new InvalidOperationException("Jwt:Secret must be configured outside Development.");
            }

            secret = DevelopmentSecret;
        }

        // HMAC zero-pads keys shorter than SHA-256's 64-byte block size. Appending
        // NUL bytes to the public development key does not change its HMAC signature.
        // Reject NULs rather than treating those equivalent encodings as distinct keys.
        if (secret.Contains("\0", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Jwt:Secret must not contain NUL characters.");
        }

        if (!environment.IsDevelopment() && string.Equals(secret, DevelopmentSecret, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The example JWT signing secret must not be used outside Development.");
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

        if (environment.IsDevelopment())
        {
            return developmentDefault;
        }

        throw new InvalidOperationException($"{name} must be configured outside Development.");
    }
}
