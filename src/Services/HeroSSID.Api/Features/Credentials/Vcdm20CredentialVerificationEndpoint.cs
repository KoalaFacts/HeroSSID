using System.Text.Json;
using HeroSSID.Api.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Opt-in HTTP boundary for direct VC Data Model 2.0 JOSE credentials.</summary>
internal static class Vcdm20CredentialVerificationEndpoint
{
    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20Credential")
            .WithSummary("Verify a directly signed VC2 credential against caller-pinned issuer and vocabulary")
            .Produces<VerifyVcdm20CredentialResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult Verify([FromBody] VerifyVcdm20CredentialRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        if (string.IsNullOrWhiteSpace(request.Credential) ||
            string.IsNullOrWhiteSpace(request.TrustedIssuerDid) ||
            string.IsNullOrWhiteSpace(request.ExpectedHolderDid) ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.SubjectContextUri is null)
        {
            return Results.Problem(title: "Invalid Request",
                detail: "Credential, caller-trusted issuer, holder, type and HTTPS claim vocabulary are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Red phase: compilation succeeds, signed valid credentials still fail closed.
        return Results.Ok(new VerifyVcdm20CredentialResponse("Invalid", null));
    }
}

/// <summary>The verification policy is provided by the authenticated caller, not inferred from the JWT.</summary>
public sealed class VerifyVcdm20CredentialRequest
{
    public string? Credential { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>Never grants business authorization, holder control or proof of current non-revocation.</summary>
public sealed record VerifyVcdm20CredentialResponse(string Status, JsonElement? VerifiedSubject);
