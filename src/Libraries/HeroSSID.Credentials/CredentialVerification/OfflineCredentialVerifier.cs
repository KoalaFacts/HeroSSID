namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Status of a local-profile credential checked alongside an issuer-signed revocation snapshot.
/// SignedNotListed does not prove issuer registration, holder possession or business authority.
/// </summary>
public enum OfflineCredentialCheckResult
{
    Invalid,
    Revoked,
    SignedNotListed
}

/// <summary>
/// Pure offline credential and snapshot checking using an explicitly trusted did:key issuer.
/// </summary>
public static class OfflineCredentialVerifier
{
    /// <summary>
    /// Verify a complete signed local vc+jwt and a fresh issuer-signed status snapshot
    /// without requiring an issuer database, DID resolver or network access.
    /// </summary>
    public static OfflineCredentialCheckResult Check(
        string credentialJwt, string snapshotJwt, string trustedIssuerDid, DateTimeOffset now)
    {
        // TDD scaffold: invalid until the verifier implements self-certifying issuer
        // binding, credential semantics, and signed snapshot verification.
        return OfflineCredentialCheckResult.Invalid;
    }
}
