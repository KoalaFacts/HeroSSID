using System.Text.Json;
using HeroSSID.Api.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Issuer trust for an externally supplied VC1.1 JWT is always verifier-owned.</summary>
internal static class JwtVcJsonTrustedIssuerVerificationEndpoint
{
    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuers")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        credentials.MapPost("/jwt-vc-json/verify-trusted-issuers-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonTrustedIssuersWithStatus")
            .Produces<VerifyJwtVcJsonTrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);
    }

    internal static IResult Verify(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock) => throw new NotSupportedException();

    internal static IResult VerifyWithStatus(
        [FromBody] VerifyJwtVcJsonTrustedIssuersRequest request,
        [FromServices] TimeProvider clock) => throw new NotSupportedException();
}

/// <summary>The caller's independently enrolled issuer keys, not untrusted JWT claims.</summary>
public sealed record class VerifyJwtVcJsonTrustedIssuersRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? TrustedIssuerDids { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
}

/// <summary>Neither signer nor subject can be disclosed on a rejected JWT/status.</summary>
public sealed record VerifyJwtVcJsonTrustedIssuersResponse(
    string Status, string? VerifiedIssuerDid, JsonElement? VerifiedSubject);
