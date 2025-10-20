namespace HeroSSID.Credentials.Models;

/// <summary>
/// Result of SD-JWT generation containing the compact SD-JWT and disclosure tokens
/// Based on IETF draft-ietf-oauth-selective-disclosure-jwt-22
/// </summary>
/// <remarks>
/// This is a MOCK model for MVP development. The actual implementation will come from
/// the HeroSD-JWT NuGet package when available.
///
/// SD-JWT Format: jwt~disclosure1~disclosure2~...~
/// Each disclosure token reveals one selectively-disclosed claim.
/// </remarks>
public sealed class SdJwtResult
{
    /// <summary>
    /// Compact SD-JWT format: jwt~disclosure1~disclosure2~...~
    /// </summary>
    /// <remarks>
    /// Format per IETF draft-22:
    /// - JWT contains hashed claims (_sd array) + regular claims
    /// - Disclosures are Base64Url-encoded JSON arrays: [salt, claim_name, claim_value]
    /// - Separator is tilde (~) between components
    /// </remarks>
    public required string CompactSdJwt { get; init; }

    /// <summary>
    /// Individual disclosure tokens (Base64Url-encoded)
    /// </summary>
    /// <remarks>
    /// Each token format: Base64Url([salt, claim_name, claim_value])
    /// Holder selects which disclosures to include in presentation to verifier.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] DisclosureTokens { get; init; }

    /// <summary>
    /// Mapping of claim names to their SHA-256 digest values in the JWT
    /// </summary>
    /// <remarks>
    /// Used internally to verify disclosure tokens match hashed claims in JWT.
    /// Format: {"claimName": "Base64Url(SHA-256(disclosure_token))"}
    /// </remarks>
    public required Dictionary<string, string> ClaimDigests { get; init; }
}
