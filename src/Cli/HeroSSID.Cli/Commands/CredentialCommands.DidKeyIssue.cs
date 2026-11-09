namespace HeroSSID.Cli.Commands;

// Test-first RED: real issuer CLI behavior is intentionally not implemented.
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyIssueParameters(
        string? IssuerDid, string? HolderDid, string? CredentialType,
        string? Context, string? SubjectFile, string? ValidFrom,
        string? ValidUntil, string? OutputFile);

    internal static bool TryIssueVc2DidKey(
        Vc2DidKeyIssueParameters parameters, Stream seedInput) =>
        throw new NotSupportedException("RED: offline direct VC2 did:key issuer not implemented.");
}
