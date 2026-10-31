using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Separates a verifier's independent emergency credential denial decision
/// from an issuer-signed private revocation snapshot.
/// </summary>
public enum JwtVcJsonVerifierPolicyResult
{
    /// <summary>No verified credential or invalid verifier policy.</summary>
    Invalid,

    /// <summary>The verifier independently denied the exact original JWT.</summary>
    DeniedByVerifier,

    /// <summary>The actual issuer's authenticated private status snapshot reported revocation.</summary>
    IssuerReportedRevoked,

    /// <summary>Issuer authenticated; revocation was not checked.</summary>
    SignedButStatusUnchecked,

    /// <summary>The issuer-signed private snapshot did not list this JWT; completeness is unproven.</summary>
    SignedNotListed
}

/// <summary>
/// Verifier-controlled, exact-original-JWT denial policy for active and retired
/// VC1.1 issuers. It does not prove holder control or human/business authorization.
/// </summary>
public static class JwtVcJsonVerifierDenylist
{
    /// <summary>
    /// Authenticates issuer, holder and credential before returning claims; a
    /// verifier-managed exact-JWT SHA-256 denial overrides authenticated trust.
    /// </summary>
    public static JwtVcJsonVerifierPolicyResult Check(
        string credentialJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("The verifier-controlled denylist is not implemented.");
    }

    /// <summary>
    /// As Check, but also requires an authentic, same-issuer private 60-second
    /// revocation snapshot. A clean snapshot cannot override local denial.
    /// </summary>
    public static JwtVcJsonVerifierPolicyResult CheckWithStatus(
        string credentialJwt,
        string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retiredCredentialPins,
        IReadOnlyCollection<string> deniedCredentialSha256,
        string expectedHolderDid,
        string expectedCredentialType,
        Uri expectedSubjectContextUri,
        DateTimeOffset now,
        out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("The verifier-controlled denylist is not implemented.");
    }
}
