namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>A verifier's short-lived request for a full-disclosure credential presentation.</summary>
/// <remarks>The verifier retains its own policy. Holder-supplied challenge metadata never establishes trust.</remarks>
public sealed record PresentationChallenge
{
    /// <summary>Cryptographically random, single-use challenge.</summary>
    public required string Nonce { get; init; }

    /// <summary>Exact verifier audience to bind into the holder proof.</summary>
    public required string Audience { get; init; }

    /// <summary>The enrolled issuer explicitly trusted by the verifier for this request.</summary>
    public required string TrustedIssuerDid { get; init; }

    /// <summary>UTC expiry; presentations cannot outlive the challenge.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
