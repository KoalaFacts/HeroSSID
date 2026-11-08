using System;

namespace HeroSSID.Cli.Commands;

/// <summary>Test-first seam for a status-aware one-use offline verifier.</summary>
internal static partial class CredentialCommands
{
    internal static bool TryVerifyVc11VerifierPresentationWithStatus(
        Vc11VerifierCheckParameters parameters,
        string? snapshotFile, string? minimumObservedAt) =>
        throw new NotSupportedException("Status-aware verifier implementation not yet provided.");
}
