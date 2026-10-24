namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Stores verifier policy and atomically consumes successful presentation challenges.</summary>
public interface IPresentationChallengeStore
{
    /// <summary>Issues a bounded-lifetime challenge owned by the verifier tenant.</summary>
    public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null);

    /// <summary>Finds a live challenge without consuming it. Unknown, expired and mismatched requests return null.</summary>
    public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce);

    /// <summary>Atomically rechecks ownership, audience and expiry, then consumes the challenge exactly once.</summary>
    public bool TryConsume(Guid verifierTenantId, string audience, string nonce);
}
