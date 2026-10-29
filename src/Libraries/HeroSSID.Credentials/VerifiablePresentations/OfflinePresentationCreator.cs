namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Holder-side creation of the local full-disclosure vp+jwt proof without an issuer database.
/// This is not OpenID4VP, selective disclosure or verifier authorization.
/// </summary>
public static class OfflinePresentationCreator
{
    /// <summary>
    /// Creates a holder-signed response for a verifier-owned challenge.
    /// The caller must explicitly approve the destination and the entire disclosed credential.
    /// The caller retains ownership of the private-key buffer.
    /// </summary>
    public static string Create(
        PresentationChallenge challenge, string credentialJwt, string holderDid,
        byte[] holderPrivateKey, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(holderPrivateKey);
        ArgumentNullException.ThrowIfNull(clock);
        throw new NotSupportedException("Holder-side offline presentation creation is not yet implemented.");
    }
}
