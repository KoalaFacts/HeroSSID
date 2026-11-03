namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Credential-free wallet delivery of the already formed OpenID4VP direct_post body.
/// Delivery is distinct from issuer authenticity, holder control and actual consent.
/// </summary>
public static class OpenId4VpJwtVcJsonWalletResponseTransport
{
    public static Task<bool> PostResponseFormAsync(
        string signedRequestJwt, string form, Uri independentlyTrustedResponseUri,
        HttpClient http, string expectedVerifierDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Direct-post transport has not been implemented.");

    public static Task<bool> PostResponseFormWithIsolatedTransportAsync(
        string signedRequestJwt, string form, Uri independentlyTrustedResponseUri,
        string expectedVerifierDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Direct-post transport has not been implemented.");
}
