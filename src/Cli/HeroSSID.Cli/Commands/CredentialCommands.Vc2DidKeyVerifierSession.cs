using System.CommandLine;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Verifier-owned local challenge session for direct VC2 did:key.
/// RED baseline: executable entry points exist but have no implementation yet.
/// </summary>
internal static partial class CredentialCommands
{
    internal static bool TryCreateVc2DidKeyVerifierRequest(
        Vc11VerifierRequestParameters parameters, Stream verifierSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(verifierSeedInput);
        return false;
    }

    internal static bool TryVerifyVc2DidKeyVerifierPresentation(
        Vc11VerifierCheckParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return false;
    }

    private static Command CreateVc2DidKeyVerifierRequestCommand() =>
        new("request-vc2-didkey", "Verifier-owned VC2 did:key signed request");

    private static Command CreateVc2DidKeyVerifierCheckCommand() =>
        new("verify-vc2-didkey-vp", "Verifier-owned VC2 did:key VP verification");
}
