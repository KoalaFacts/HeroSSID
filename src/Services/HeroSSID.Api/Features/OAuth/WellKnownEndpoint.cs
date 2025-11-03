using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.OAuth;

/// <summary>
/// OAuth 2.0 Authorization Server Metadata endpoint (T068).
/// Per RFC 8414 - OAuth 2.0 Authorization Server Metadata.
/// </summary>
public static class WellKnownEndpoint
{
    /// <summary>
    /// Maps the OAuth 2.0 authorization server metadata endpoint.
    /// </summary>
    public static IEndpointRouteBuilder MapOAuthMetadataEndpoint(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/.well-known/oauth-authorization-server", GetAuthorizationServerMetadata)
            .AllowAnonymous()
            .WithName("OAuthMetadata")
            .WithTags("OAuth", ".well-known")
            .WithOpenApi();

        return endpoints;
    }

    /// <summary>
    /// Returns OAuth 2.0 authorization server metadata per RFC 8414 (T068).
    /// </summary>
    private static IResult GetAuthorizationServerMetadata(
        HttpContext httpContext,
        [FromServices] ILogger<Program> logger)
    {
        // Get the base URL from the request
        var baseUrl = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}";

        // T069: Log metadata request
        logger.LogInformation("OAuth authorization server metadata requested from {RemoteIpAddress}",
            httpContext.Connection.RemoteIpAddress);

        var metadata = new
        {
            // RFC 8414 REQUIRED fields
            issuer = baseUrl,
            token_endpoint = $"{baseUrl}/oauth2/token",

            // RFC 8414 RECOMMENDED fields
            grant_types_supported = new[]
            {
                "client_credentials"
                // "urn:ietf:params:oauth:grant-type:pre-authorized_code" will be added in User Story 2
            },
            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_post",
                "client_secret_basic"
            },
            scopes_supported = new[]
            {
                "credential:issue",
                "credential:verify"
            },
            response_types_supported = new[]
            {
                "token" // For client credentials flow
            },

            // Additional metadata
            service_documentation = $"{baseUrl}/api/docs",
            code_challenge_methods_supported = new[] { "S256" } // For future PKCE support
        };

        return Results.Json(metadata);
    }
}
