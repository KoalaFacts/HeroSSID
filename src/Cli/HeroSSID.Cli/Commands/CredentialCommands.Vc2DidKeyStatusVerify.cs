namespace HeroSSID.Cli.Commands;

/// <summary>
/// The unimplemented verifier entry point is intentionally present so
/// genuine SDK-signed status integration tests compile and fail at runtime.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyStatusVerifyParameters(
        string? JwtFile, string? SnapshotFile, string? TrustedIssuer,
        string? HolderDid, string? CredentialType, string? Context,
        string? MinimumObservedAt);

    internal static bool TryVerifyVc2DidKeyStatus(
        Vc2DidKeyStatusVerifyParameters parameters, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        throw new NotSupportedException("RED: the VC2 did:key status verifier is not implemented.");
    }
}
