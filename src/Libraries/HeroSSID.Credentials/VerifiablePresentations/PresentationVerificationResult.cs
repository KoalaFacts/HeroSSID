namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Result of verifying a Verifiable Presentation
/// </summary>
public sealed class PresentationVerificationResult
{
    /// <summary>
    /// Indicates if the presentation is valid (all credentials valid, signatures valid)
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Verification status code
    /// </summary>
    public required PresentationVerificationStatus Status { get; init; }

    /// <summary>
    /// Detailed validation error messages (empty if valid)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] ValidationErrors { get; init; }

    /// <summary>
    /// Disclosed claims from all credentials in the presentation
    /// Only contains claims that holder chose to disclose
    /// </summary>
    public Dictionary<string, object>? DisclosedClaims { get; init; }

    /// <summary>
    /// Holder/presenter DID identifier
    /// </summary>
    public string? HolderDid { get; init; }

    /// <summary>
    /// Issuer DID identifiers for credentials in the presentation
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public string[]? IssuerDids { get; init; }
}

/// <summary>
/// Status codes for Verifiable Presentation verification
/// </summary>
public enum PresentationVerificationStatus
{
    /// <summary>All credentials valid, all disclosures valid</summary>
    Valid,

    /// <summary>One or more credential signatures invalid</summary>
    CredentialSignatureInvalid,

    /// <summary>One or more disclosure tokens don't match credential hash digests</summary>
    DisclosureMismatch,

    /// <summary>VP-JWT format invalid or unparseable</summary>
    MalformedPresentation,

    /// <summary>Credential issuer DID not found</summary>
    IssuerNotFound,

    /// <summary>One or more credentials expired</summary>
    CredentialExpired
}
