namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Result of credential verification operation.
/// </summary>
public sealed class CredentialVerificationResult
{
    /// <summary>
    /// Indicates whether the supported local VC structure, issuer signature, time policy and local revocation checks succeeded.
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
    /// Issuer-signed subject claims returned only after successful verification.
    /// The verifier returns null on failure. Acceptance of these claims remains a relying-party decision.
    /// </summary>
    public Dictionary<string, object>? CredentialSubject { get; init; }

    /// <summary>
    /// Issuer DID returned after successful verification; null on failure.
    /// A verified signature does not establish that the issuer is trusted for a business purpose.
    /// </summary>
    public string? IssuerDid { get; init; }

    /// <summary>
    /// Credential expiration timestamp after successful verification.
    /// Null on failure or when a valid credential has no expiration.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
