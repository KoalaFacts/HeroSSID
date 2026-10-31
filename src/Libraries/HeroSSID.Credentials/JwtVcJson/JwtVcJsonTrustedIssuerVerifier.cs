using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Verifier-owned, offline trust for historical/current JWT VC 1.1 issuers.
/// An issuer's valid signature is not holder control, identity verification,
/// consent, delegation, or business authorization.
/// </summary>
public enum JwtVcJsonTrustedIssuerCheckResult
{
    Invalid,
    Revoked,
    SignedButStatusUnchecked,
    SignedNotListed
}

/// <summary>Independent verifier-owned trust policy across at most 16 did:key issuers.</summary>
public static class JwtVcJsonTrustedIssuerVerifier
{
    public static JwtVcJsonTrustedIssuerCheckResult Check(
        string credentialJwt, IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Offline issuer trust has not been implemented.");
    }

    public static JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        throw new NotSupportedException("Offline issuer trust status has not been implemented.");
    }
}
