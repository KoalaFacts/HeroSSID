using HeroSSID.Credentials.CredentialRevocation;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Issuer-signed, 60-second, format-specific revocation export for jwt_vc_json.
/// This private snapshot is NOT a standard W3C Bitstring Status List.
/// </summary>
public static class JwtVcJsonRevocationSnapshot
{
    /// <summary>Create from the issuer's complete authoritative revoked VC1.1 JWT set.</summary>
    public static string Create(string issuerDid, IReadOnlyCollection<string> revokedCredentialJwts,
        byte[] issuerSeed, DateTimeOffset observedAt, TimeProvider clock) =>
        throw new NotSupportedException("JWT VC 1.1 revocation exports are not implemented.");

    /// <summary>Verify issuer signature and exact original credential membership.</summary>
    public static RevocationSnapshotCheckResult Check(string snapshotJwt, string credentialJwt,
        string trustedIssuerDid, DateTimeOffset now) =>
        throw new NotSupportedException("JWT VC 1.1 revocation validation is not implemented.");
}
