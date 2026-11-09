namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated VC2 Agent scope full-disclosure proof. No issuer authority,
/// legal identity or business authorization is conferred by the holder.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeHolderParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience, string? TrustedIssuerDid,
        string? AgentDid, string? Context, string? CredentialId,
        string? Resource, string? Action, string? OutputJwtFile,
        bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc2AgentScope(
        Vc2AgentScopeHolderParameters parameters, Stream agentSeedInput) =>
        throw new NotSupportedException("Test-first VC2 Agent holder CLI not implemented.");
}
