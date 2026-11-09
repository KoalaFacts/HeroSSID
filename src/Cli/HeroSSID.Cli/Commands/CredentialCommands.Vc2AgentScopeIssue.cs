using System.CommandLine;

namespace HeroSSID.Cli.Commands;

/// <summary>Issuer-controlled offline VC2 agent scope issuance.</summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeIssueParameters(
        string? IssuerDid, string? AgentDid, string? Context,
        string? CredentialId, string? Audience, string? Resource,
        string? Action, string? ValidFrom, string? ValidUntil, string? OutputFile);

    internal static bool TryIssueVc2AgentScope(
        Vc2AgentScopeIssueParameters parameters, Stream seedInput)
    {
        throw new NotSupportedException("Test-first CLI issuer is not implemented.");
    }
}
