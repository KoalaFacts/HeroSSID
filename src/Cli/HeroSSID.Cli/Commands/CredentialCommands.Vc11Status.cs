using System;
using System.IO;
using System.CommandLine;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline issuer-issued status and independently pinned VC1.1 status checks.
/// No real-time status or holder proof is inferred from a snapshot.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11StatusIssueParameters(
        string? IssuerDid, string? RevokedJwtManifestFile,
        string? OutputSnapshotFile, string? ObservedAt);

    internal sealed record Vc11StatusVerifyParameters(
        Vc11PinnedVerifyParameters Pins, string? SnapshotFile,
        string? MinimumObservedAt);

    internal static bool TryIssueVc11DidKeyStatus(
        Vc11StatusIssueParameters parameters, Stream issuerSeedInput,
        TimeProvider clock) =>
        throw new NotSupportedException("VC1.1 issuer status CLI not implemented.");

    internal static bool TryVerifyVc11DidKeyPinnedStatus(
        Vc11StatusVerifyParameters parameters, DateTimeOffset observedAt) =>
        throw new NotSupportedException("VC1.1 pinned status verifier CLI not implemented.");

    private static Command CreateVc11StatusIssueCommand() =>
        new("issue-vc11-didkey-status", "Issue private VC1.1 signed revocation snapshot");

    private static Command CreateVc11StatusVerifyCommand() =>
        new("verify-vc11-didkey-pinned-status", "Verify VC1.1 original issuer signature and signed revocation snapshot");
}
