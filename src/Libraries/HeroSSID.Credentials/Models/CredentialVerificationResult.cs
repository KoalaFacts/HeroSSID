namespace HeroSSID.Credentials.Models;

/// <summary>
/// Result of credential verification operation.
/// </summary>
public sealed class CredentialVerificationResult
{
    /// <summary>
    /// Indicates if the credential is valid (signature valid + not expired).
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
    /// Parsed credential subject claims (null if invalid).
    /// </summary>
    public Dictionary<string, object>? CredentialSubject { get; init; }

    /// <summary>
    /// Issuer DID identifier (null if malformed JWT).
    /// </summary>
    public string? IssuerDid { get; init; }

    /// <summary>
    /// Credential expiration timestamp (null if no expiration).
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
