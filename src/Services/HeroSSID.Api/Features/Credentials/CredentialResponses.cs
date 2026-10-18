namespace HeroSSID.Api.Features.Credentials;

/// <summary>Issued JWT verifiable credential.</summary>
public sealed record IssueCredentialResponse(string Credential);

/// <summary>Verification outcome; DID values are populated only for a verified credential.</summary>
public sealed record VerifyCredentialResponse(bool IsValid, string? IssuerDid, string? HolderDid);
