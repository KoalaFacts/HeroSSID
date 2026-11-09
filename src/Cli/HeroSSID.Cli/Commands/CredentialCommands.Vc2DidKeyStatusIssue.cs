using System.CommandLine;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-owned offline direct VC2 did:key status publication.
/// Never confuses an issuer observation with live status or authorization.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyStatusIssueParameters(
        string? IssuerDid, string? RevokedJwtListFile,
        string? ObservedAt, string? OutputFile);

    internal static bool TryIssueVc2DidKeyStatus(
        Vc2DidKeyStatusIssueParameters parameters, Stream seedInput) =>
        throw new NotSupportedException("Runtime RED: issuer VC2 did:key status CLI not implemented.");

    private static Command CreateVc2DidKeyStatusIssueCommand() =>
        throw new NotSupportedException("Runtime RED: issuer VC2 did:key status command not implemented.");
}
