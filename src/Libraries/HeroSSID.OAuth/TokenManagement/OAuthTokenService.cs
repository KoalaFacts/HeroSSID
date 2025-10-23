namespace HeroSSID.OAuth.TokenManagement;

/// <summary>
/// Service for OAuth 2.0 token operations.
/// Feature: Token Management
/// </summary>
public interface IOAuthTokenService
{
    /// <summary>
    /// Issues an OAuth 2.0 access token for the specified client.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="clientSecret">The client secret.</param>
    /// <param name="scopes">Requested scopes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Access token response with token and expiration.</returns>
    public Task<OAuthTokenResponse> IssueClientCredentialsTokenAsync(
        string clientId,
        string clientSecret,
        string[] scopes,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates an access token.
    /// </summary>
    /// <param name="token">The access token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token validation result with claims if valid.</returns>
    public Task<TokenValidationResult> ValidateTokenAsync(
        string token,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// OAuth token response.
/// </summary>
public sealed record OAuthTokenResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string? Scope);

/// <summary>
/// Token validation result.
/// </summary>
#pragma warning disable CA1819 // Properties should not return arrays - scopes array is part of OAuth spec
public sealed record TokenValidationResult(
    bool IsValid,
    string? TenantId,
    string? ClientId,
    string[]? Scopes,
    string? ErrorMessage);
#pragma warning restore CA1819
