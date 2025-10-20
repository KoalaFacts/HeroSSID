namespace HeroSSID.Credentials.Models;

/// <summary>
/// Verification status codes for credential validation results.
/// </summary>
public enum VerificationStatus
{
    /// <summary>Signature valid, not expired, issuer found</summary>
    Valid,

    /// <summary>Signature invalid (tampered or wrong key)</summary>
    SignatureInvalid,

    /// <summary>Credential expiration date passed</summary>
    Expired,

    /// <summary>Issuer DID not found in database</summary>
    IssuerNotFound,

    /// <summary>JWT format invalid or unparseable</summary>
    MalformedJwt,

    /// <summary>Credential has been revoked by issuer</summary>
    Revoked
}
