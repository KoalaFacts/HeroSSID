namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Result of creating a Verifiable Presentation with selective disclosure
/// </summary>
public sealed class PresentationResult
{
    /// <summary>
    /// VP-JWT in compact serialization format
    /// Contains one or more credentials with selectively disclosed claims
    /// </summary>
    public required string PresentationJwt { get; init; }

    /// <summary>
    /// Selected disclosure tokens included in this presentation
    /// Holder controls which claims to reveal to verifier
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] SelectedDisclosures { get; init; }

    /// <summary>
    /// Claim names that were disclosed in this presentation
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Immutable result object with init-only array property")]
    public required string[] DisclosedClaimNames { get; init; }
}
