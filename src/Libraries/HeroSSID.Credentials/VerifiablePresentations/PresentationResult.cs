namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Result of creating a full-disclosure, issuer-preserving presentation
/// </summary>
public sealed class PresentationResult
{
    /// <summary>
    /// VP-JWT in compact serialization format
    /// Contains the complete original credential, including all its claims
    /// </summary>
    public required string PresentationJwt { get; init; }

    /// <summary>
    /// Always empty for this full-disclosure profile. Retained for legacy source compatibility.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] SelectedDisclosures { get; init; }

    /// <summary>
    /// All credential-subject claim names disclosed in this presentation
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] DisclosedClaimNames { get; init; }
}
