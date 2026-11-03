namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Opt-in, bounded and volatile signed Request Object host-side storage.
/// Single-instance only; not a durable or distributed host.
/// </summary>
public sealed class OpenId4VpJwtVcJsonRequestObjectStore(
    IPresentationChallengeStore challenges, TimeProvider clock)
{
    /// <summary>Publish an authentic, live and verifier-owned signed request under an opaque reference.</summary>
    public string Publish(Guid tenantId, string signedRequestJwt, string trustedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri)
    {
        _ = challenges;
        _ = clock;
        throw new NotSupportedException("Test-first runtime failure: Request Object publication is not implemented.");
    }

    /// <summary>Retrieve the unchanged original JWT only while its challenge is live.</summary>
    public bool TryGet(string opaqueReference, out string signedRequestJwt)
    {
        signedRequestJwt = string.Empty;
        _ = challenges;
        throw new NotSupportedException("Test-first runtime failure: Request Object retrieval is not implemented.");
    }
}
