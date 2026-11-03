namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// A challenge store that can persist a distinct hosted Request Object nonce
/// purpose. Unsupported custom stores must fail closed rather than issue an
/// ordinary by-value challenge for an OpenID4VP request_uri.
/// </summary>
public interface IHostedPresentationChallengeStore : IPresentationChallengeStore
{
    /// <summary>
    /// Issue a one-use challenge marked for a hosted original Request Object.
    /// Implementations must enforce capacity and atomic consumption as for Issue.
    /// </summary>
    public PresentationChallenge IssueHosted(
        Guid verifierTenantId, string audience, string trustedIssuerDid,
        TimeSpan? lifetime = null);
}
