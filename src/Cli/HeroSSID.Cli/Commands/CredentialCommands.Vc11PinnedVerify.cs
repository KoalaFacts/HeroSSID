using System;

namespace HeroSSID.Cli.Commands;

/// <summary>Verifier-owned pins for an original VC Data Model 1.1 jwt_vc_json JWT.</summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11PinnedVerifyParameters(
        string? JwtFile, string? TrustedIssuer, string? IssuerName,
        string? CredentialId, string? HolderDid, string? CredentialType,
        string? Context);

    internal static bool TryVerifyVc11DidKeyPinned(
        Vc11PinnedVerifyParameters parameters, DateTimeOffset observedAt)
        => throw new NotSupportedException("VC1.1 pinned did:key CLI verifier not implemented");
}
