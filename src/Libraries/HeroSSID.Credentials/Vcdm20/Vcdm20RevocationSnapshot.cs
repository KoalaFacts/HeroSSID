using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>Result of an offline VC2 credential or presentation status check.</summary>
public enum Vcdm20RevocationCheckResult
{
    Invalid,
    Revoked,
    SignedNotListed
}

/// <summary>Issuer-signed bounded VC2 digest status, not a W3C status list.</summary>
public static class Vcdm20RevocationSnapshot
{
    public static string Create(string issuerDid, IReadOnlyCollection<string> revokedCredentialJwts,
        byte[] issuerSeed, DateTimeOffset observedAt, TimeProvider clock) =>
        throw new NotSupportedException("VC2 status issuance has not been implemented.");

    public static Vcdm20RevocationCheckResult Check(string snapshotJwt, string credentialJwt,
        string trustedIssuerDid, DateTimeOffset now) => Vcdm20RevocationCheckResult.Invalid;

    public static Vcdm20RevocationCheckResult CheckPresentation(
        string presentationJwt, string snapshotJwt, Guid tenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return Vcdm20RevocationCheckResult.Invalid;
    }
}
