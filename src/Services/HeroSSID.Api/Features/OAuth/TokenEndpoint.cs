using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Data;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace HeroSSID.Api.Features.OAuth;

/// <summary>
/// OAuth 2.0 token endpoint for client credentials grant (T063).
/// Simple JWT-based implementation.
/// </summary>
public static class TokenEndpoint
{
    /// <summary>
    /// Maps the OAuth 2.0 token endpoint.
    /// </summary>
    public static IEndpointRouteBuilder MapTokenEndpoint(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/oauth2/token", HandleTokenRequestAsync)
            .AllowAnonymous()
            .WithName("OAuthToken")
            .WithTags("OAuth")
            .WithOpenApi();

        return endpoints;
    }

    /// <summary>
    /// Handles OAuth 2.0 token requests (T063, T064).
    /// Supports client_credentials grant type with tenant isolation.
    /// </summary>
    private static async Task<IResult> HandleTokenRequestAsync(
        HttpContext httpContext,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IConfiguration configuration,
        [FromServices] ILogger<Program> logger)
    {
        // Parse form data
        var form = await httpContext.Request.ReadFormAsync().ConfigureAwait(false);
        var grantType = form["grant_type"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        var scope = form["scope"].ToString();

        // T064: Validate grant type exists
        if (string.IsNullOrEmpty(grantType))
        {
            return Results.Json(
                new
                {
                    error = "invalid_request",
                    error_description = "The grant_type parameter is missing."
                },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Validate grant type is supported
        if (grantType != "client_credentials")
        {
            logger.LogWarning("OAuth token request failed: Unsupported grant type {GrantType}", grantType);
            return Results.Json(
                new
                {
                    error = "unsupported_grant_type",
                    error_description = $"The grant type '{grantType}' is not supported."
                },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Validate client_id
        if (string.IsNullOrEmpty(clientId))
        {
            return Results.Json(
                new
                {
                    error = "invalid_client",
                    error_description = "The client_id is missing."
                },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Validate client_secret
        if (string.IsNullOrEmpty(clientSecret))
        {
            return Results.Json(
                new
                {
                    error = "invalid_client",
                    error_description = "The client_secret is missing."
                },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Find client in database
        var client = await dbContext.OAuthClients
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsEnabled);

        if (client == null)
        {
            logger.LogWarning("OAuth token request failed: Client {ClientId} not found", clientId);
            return Results.Json(
                new
                {
                    error = "invalid_client",
                    error_description = "The specified client_id is invalid."
                },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        // Verify client secret
        if (!VerifySecret(clientSecret, client.ClientSecretHash))
        {
            logger.LogWarning("OAuth token request failed: Invalid client secret for {ClientId}", clientId);
            return Results.Json(
                new
                {
                    error = "invalid_client",
                    error_description = "The specified client credentials are invalid."
                },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        // Validate requested scopes
        var requestedScopes = string.IsNullOrEmpty(scope)
            ? Array.Empty<string>()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var allowedScopes = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var requestedScope in requestedScopes)
        {
            if (!allowedScopes.Contains(requestedScope))
            {
                logger.LogWarning("OAuth token request failed: Scope {Scope} not allowed for client {ClientId}",
                    requestedScope, clientId);
                return Results.Json(
                    new
                    {
                        error = "invalid_scope",
                        error_description = $"The scope '{requestedScope}' is not allowed for this client."
                    },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        }

        // Generate JWT token
        var token = GenerateJwtToken(client, requestedScopes, configuration);

        // T069: Log successful token issuance
        logger.LogInformation(
            "OAuth access token issued for client {ClientId}, tenant {TenantId}, scopes {Scopes}",
            clientId,
            client.TenantId,
            scope ?? "none");

        // Return OAuth 2.0 token response
        return Results.Json(new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = 3600,
            scope = string.Join(" ", requestedScopes)
        });
    }

    /// <summary>
    /// Generate a JWT access token for the client.
    /// </summary>
    private static string GenerateJwtToken(
        HeroSSID.Data.Entities.OAuthClient client,
        string[] scopes,
        IConfiguration configuration)
    {
        // Get JWT settings from configuration (or use defaults for development)
        var jwtSecret = configuration["Jwt:Secret"] ?? "your-256-bit-secret-key-change-in-production-min-32-chars";
        var jwtIssuer = configuration["Jwt:Issuer"] ?? "https://herossid.api";
        var jwtAudience = configuration["Jwt:Audience"] ?? "https://herossid.api";

        // Create claims
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, client.ClientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("client_id", client.ClientId),
            new("tenant_id", client.TenantId.ToString())
        };

        // Add scope claims
        foreach (var scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        // Create signing credentials
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Create token
        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: jwtAudience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Verify a client secret against the stored hash.
    /// </summary>
#pragma warning disable CA1031 // Catch general exceptions for security - don't leak hash format details
    private static bool VerifySecret(string secret, string storedHash)
    {
        try
        {
            // Decode the stored hash
            byte[] hashBytes = Convert.FromBase64String(storedHash);

            // Extract salt (first 16 bytes)
            byte[] salt = new byte[128 / 8];
            Array.Copy(hashBytes, 0, salt, 0, salt.Length);

            // Hash the provided secret with the same salt
            byte[] hash = KeyDerivation.Pbkdf2(
                password: secret,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8);

            // Compare hashes (constant time comparison)
            for (int i = 0; i < hash.Length; i++)
            {
                if (hashBytes[i + salt.Length] != hash[i])
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
#pragma warning restore CA1031
}
