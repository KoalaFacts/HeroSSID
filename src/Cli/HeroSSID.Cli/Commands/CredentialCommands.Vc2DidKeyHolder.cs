using System.IO;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated, offline direct VC2 did:key presentation entry point.
/// The wallet keeps and presents the original issuer statement; it cannot
/// change who signed it or grant the receiving application's authority.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyHolderParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience,
        string? TrustedIssuerDid, string? HolderDid,
        string? CredentialType, string? Context,
        string? OutputJwtFile, bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc2DidKey(
        Vc2DidKeyHolderParameters parameters, Stream holderSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(holderSeedInput);
        throw new NotSupportedException("VC2 holder CLI not implemented yet.");
    }
}
