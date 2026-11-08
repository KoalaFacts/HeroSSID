namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline VC1.1 jwt_vc_json issuer command, deliberately distinct from
/// legacy private vc.context or any holder control assertion.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11IssueParameters(
        string? IssuerDid, string? IssuerName, string? CredentialId,
        string? HolderDid, string? CredentialType, string? Context,
        string? SubjectFile, string? ValidFrom, string? ValidUntil,
        string? OutputFile);

    internal static bool TryIssueVc11DidKey(
        Vc11IssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);
        throw new NotSupportedException("Test-first: offline VC1.1 issuer CLI not implemented.");
    }
}
