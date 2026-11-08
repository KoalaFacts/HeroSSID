namespace HeroSSID.Cli.Commands;

/// <summary>
/// Verifier-owned, single-machine offline VC1.1 challenge and presentation session.
/// This is a private local-file profile, not a hosted OpenID4VP verifier.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11VerifierRequestParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? CredentialType, string? Context,
        string? RequestJwtFile, string? SessionFile, int LifetimeSeconds);

    internal sealed record Vc11VerifierCheckParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? CredentialType, string? Context,
        string? RequestJwtFile, string? SessionFile, string? PresentationJwtFile);

    internal static bool TryCreateVc11VerifierRequest(
        Vc11VerifierRequestParameters parameters, Stream verifierSeedInput) =>
        throw new NotSupportedException("Verifier-owned offline request persistence is not implemented.");

    internal static bool TryVerifyVc11VerifierPresentation(
        Vc11VerifierCheckParameters parameters) =>
        throw new NotSupportedException("Verifier-owned atomic challenge consumption is not implemented.");
}
