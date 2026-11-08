namespace HeroSSID.Cli.Commands;

/// <summary>
/// A test-first implementation placeholder for exact verifier-owned signed-claim checks.
/// No success response is permitted until original issuer verification and claim matching exist.
/// </summary>
internal static partial class CredentialCommands
{
    internal static bool TryVerifyVc11DidKeyPinnedClaim(
        Vc11PinnedVerifyParameters parameters, string? claimName,
        string? claimValue, DateTimeOffset observedAt) =>
        throw new NotSupportedException("VC1.1 signed-claim validation is not implemented.");
}
