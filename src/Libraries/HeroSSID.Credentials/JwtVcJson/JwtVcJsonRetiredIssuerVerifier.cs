using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Independently registered SHA-256 of one specific authentic credential
/// issued with a retired Ed25519 did:key. A DID alone is NOT an enrollment.
/// </summary>
public sealed record JwtVcJsonRetiredCredentialPin(string IssuerDid, string CredentialSha256);

/// <summary>
/// Verifier-owned transition policy: active issuer keys can issue new credentials;
/// a retired key can only authenticate exact previously pinned credential JWTs.
/// This never auto-enrolls issuers or creates a business authorization.
/// </summary>
public static class JwtVcJsonRetiredIssuerVerifier
{
    /// <summary>
    /// Verify a current issuer or a previously registered exact credential
    /// from a retired issuer. A signature or backdated iat alone cannot
    /// enroll a new JWT from a retired signing key.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult Check(
        string credentialJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Implement exact historical credential pinning.");
    }

    /// <summary>
    /// Additionally require a fresh private issuer-signed status snapshot
    /// bound to the actual signing issuer; signed absence is not live status.
    /// </summary>
    public static JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string credentialJwt,
        string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Implement exact historical credential pinning.");
    }
}
