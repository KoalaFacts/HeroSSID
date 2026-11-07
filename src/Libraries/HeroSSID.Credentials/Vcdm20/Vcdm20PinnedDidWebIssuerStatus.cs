using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>Issuer-signed short-lived did:web VC2 status; explicitly non-standard.</summary>
public static class Vcdm20PinnedDidWebIssuerStatus
{
    public static string Create(
        string issuerDid, string assertionMethodId, byte[] issuerSeed,
        byte[] issuerPublicKey, string issuerName,
        IReadOnlyCollection<string> revokedCredentialJwts,
        DateTimeOffset observedAt, TimeProvider clock) =>
        throw new NotSupportedException("Not implemented.");

    public static Vcdm20RevocationCheckResult Check(
        string snapshotJwt, string credentialJwt,
        string trustedIssuerDid, string trustedAssertionMethodId,
        byte[] pinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, Uri expectedAudience, string expectedHolderDid,
        string expectedCredentialType, Uri expectedContextUri,
        DateTimeOffset minimumObservedAtUtc, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("Not implemented.");
    }
}
