using System;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-owned offline signed status export. Test-first placeholder;
/// it must never be treated as a working CLI command before the runtime RED.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidWebStatusIssueParameters(
        string? IssuerDid, string? VerificationMethod, string? PublicKeyHex,
        string? IssuerName, string? RevokedJwtListFile, string? ObservedAt,
        string? OutputFile);

    internal static bool TryIssueVc2DidWebStatus(
        Vc2DidWebStatusIssueParameters parameters, Stream seedInput) =>
        throw new NotSupportedException("Status issuer CLI implementation not yet installed.");
}
