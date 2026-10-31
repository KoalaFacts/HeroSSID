using System.Text.Json;
using HeroSSID.Api.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Independent verifier-owned issuer trust for direct VC2 JWTs.</summary>
internal static class Vcdm20TrustedIssuerVerificationEndpoint
{
    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify-trusted-issuers", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuers")
            .WithSummary("Verify direct VC2 credential against an independently enrolled issuer DID allowlist")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        credentials.MapPost("/vcdm20/verify-trusted-issuers-with-status", VerifyWithStatus)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20TrustedIssuersWithStatus")
            .WithSummary("Verify direct VC2 credential and status using its authenticated issuer signer")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);
    }

    internal static IResult Verify(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock) =>
        throw new NotSupportedException("Implement issuer-trust HTTP verification after runtime red.");

    internal static IResult VerifyWithStatus(
        [FromBody] VerifyVcdm20TrustedIssuersRequest request,
        [FromServices] TimeProvider clock) =>
        throw new NotSupportedException("Implement signer-bound issuer status verification after runtime red.");
}

/// <summary>Policy is owned by the verifier; never infer trust from a JWT or successor proof.</summary>
public sealed class VerifyVcdm20TrustedIssuersRequest
{
    public string? Credential { get; init; }
    public string[]? TrustedIssuerDids { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
}

/// <summary>Issuer attestation only; neither holder control nor business authorization.</summary>
public sealed record VerifyVcdm20TrustedIssuersResponse(
    string Status, string? VerifiedIssuerDid, JsonElement? VerifiedSubject);
