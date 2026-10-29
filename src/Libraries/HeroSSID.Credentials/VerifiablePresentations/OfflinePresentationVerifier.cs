namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Outcome of an offline, full-disclosure holder presentation check.</summary>
public enum OfflinePresentationCheckResult
{
    Invalid,
    Revoked,
    SignedNotListed
}

/// <summary>
/// Independently verifies an issuer-signed credential, holder-signed presentation
/// and issuer-signed revocation snapshot against a verifier-owned single-use challenge.
/// </summary>
public static class OfflinePresentationVerifier
{
    /// <summary>Checks an untrusted presentation without access to the issuer database.</summary>
    public static OfflinePresentationCheckResult Check(
        string presentationJwt, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, IPresentationChallengeStore challenges,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        return OfflinePresentationCheckResult.Invalid;
    }
}
