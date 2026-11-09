using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeVerifierRequestParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? Context,
        string? RequestJwtFile, string? SessionFile, int LifetimeSeconds);

    internal static bool TryCreateVc2AgentScopeVerifierRequest(
        Vc2AgentScopeVerifierRequestParameters parameters, Stream verifierSeedInput) =>
        throw new NotSupportedException("VC2 agent scope verifier session is not yet implemented.");

    internal static bool TryVerifyVc2AgentScopePresentationWithStatus(
        Vc11VerifierCheckParameters parameters, string? agentDid,
        string? credentialId, string? resource, string? action,
        string? snapshotFile, string? minimumObservedAt) =>
        throw new NotSupportedException("VC2 agent scope one-use status verification is not yet implemented.");
}
