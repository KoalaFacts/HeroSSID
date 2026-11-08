namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated full-disclosure VC1.1 JWT VP from an authenticated verifier
/// request. Only the holder signs; issuer provenance and independent verifier
/// pins must be checked before disclosure.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11HolderPresentationParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience,
        string? TrustedIssuerDid, string? IssuerName, string? CredentialId,
        string? HolderDid, string? CredentialType, string? Context,
        string? OutputJwtFile, bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc11DidKey(
        Vc11HolderPresentationParameters parameters, Stream holderSeedInput) =>
        throw new NotSupportedException("Holder-operated VC1.1 CLI presentation not implemented.");
}
