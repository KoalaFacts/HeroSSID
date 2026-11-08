using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifier-owned composition of an issuer-signed agent scope, a genuinely
/// holder-signed single-use presentation and a separate issuer status snapshot.
/// Does not perform business authorization or establish real-world identity.
/// </summary>
public static class Vcdm20AgentScopePresentation
{
    /// <summary>
    /// Require independent issuer, agent, purpose, recipient and request pins;
    /// release the scope only on all successful cryptographic and one-use gates.
    /// SignedNotListed is a bounded issuer observation, not live status.
    /// </summary>
    public static Vcdm20RevocationCheckResult CheckWithIssuerStatus(
        string presentationJwt, string signedRequestJwt, string trustedRequestSha256,
        string trustedVerifierDid, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string expectedAgentDid, Uri expectedContextUri, Uri expectedCredentialId,
        Uri expectedRecipient, Uri expectedResource, string expectedAction,
        DateTimeOffset minimumObservedAtUtc, IPresentationChallengeStore challenges,
        TimeProvider clock, out JsonElement verifiedScope)
    {
        verifiedScope = default;
        throw new NotSupportedException("Implement the independently pinned agent holder/status verification gate.");
    }
}
