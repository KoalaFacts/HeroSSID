namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Result of credential verification operation.
/// </summary>
public sealed class CredentialVerificationResult
{
    /// <summary>
    /// Indicates whether issuer, signature, expiration and local revocation checks succeeded.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Specific verification status code.
    /// </summary>
    public required VerificationStatus Status { get; init; }

    /// <summary>
    /// Detailed validation error messages (empty if valid).
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] ValidationErrors { get; init; }

    /// <summary>
    /// Parsed credential subject claims. Some failure results retain untrusted parsed values;
    /// callers must require IsValid before using them as verified claims.
    /// </summary>
    public Dictionary<string, object>? CredentialSubject { get; init; }

    /// <summary>
    /// Parsed issuer DID identifier. Trust it only when IsValid is true.
    /// </summary>
    public string? IssuerDid { get; init; }

    /// <summary>
    /// Credential expiration timestamp (null if no expiration).
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
