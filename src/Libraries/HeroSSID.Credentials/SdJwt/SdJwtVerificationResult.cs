namespace HeroSSID.Credentials.SdJwt;

/// <summary>
/// Result of SD-JWT verification with reconstructed disclosed claims
/// Based on IETF draft-ietf-oauth-selective-disclosure-jwt-22
/// </summary>
/// <remarks>
/// This is a MOCK model for MVP development. The actual implementation will come from
/// the HeroSD-JWT NuGet package when available.
/// </remarks>
public sealed class SdJwtVerificationResult
{
    /// <summary>
    /// Indicates if the SD-JWT signature is valid and disclosures match hash digests
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Verification status code
    /// </summary>
    public required SdJwtVerificationStatus Status { get; init; }

    /// <summary>
    /// Detailed validation error messages (empty if valid)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] ValidationErrors { get; init; }

    /// <summary>
    /// Reconstructed claims from disclosed disclosures only
    /// Does NOT include undisclosed claims (privacy-preserving)
    /// </summary>
    public Dictionary<string, object>? DisclosedClaims { get; init; }

    /// <summary>
    /// Issuer DID identifier extracted from JWT
    /// </summary>
    public string? IssuerDid { get; init; }

    /// <summary>
    /// Holder/subject DID identifier extracted from JWT
    /// </summary>
    public string? HolderDid { get; init; }
}

/// <summary>
/// Status codes for SD-JWT verification
/// </summary>
public enum SdJwtVerificationStatus
{
    /// <summary>Signature valid, all disclosures match hash digests</summary>
    Valid,

    /// <summary>Signature invalid (tampered or wrong key)</summary>
    SignatureInvalid,

    /// <summary>One or more disclosure tokens don't match hash digests in JWT</summary>
    DisclosureMismatch,

    /// <summary>SD-JWT format invalid or unparseable</summary>
    MalformedSdJwt,

    /// <summary>Issuer DID not found or invalid</summary>
    IssuerNotFound
}
