namespace HeroSSID.Api.Features.Credentials;

/// <summary>Request to issue a JWT verifiable credential using existing DIDs.</summary>
public sealed class IssueCredentialRequest
{
    public string? IssuerDid { get; init; }
    public string? HolderDid { get; init; }
    public string? CredentialType { get; init; }
    public Dictionary<string, object>? Claims { get; init; }
}

/// <summary>JWT verifiable credential to verify.</summary>
public sealed class VerifyCredentialRequest
{
    public string? Credential { get; init; }
}
