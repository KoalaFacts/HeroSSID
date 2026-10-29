using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Opt-in HTTP boundary for direct VC Data Model 2.0 JOSE credentials.</summary>
internal static class Vcdm20CredentialVerificationEndpoint
{
    private const int MaximumJwtLength = 65_536;

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

    /// <summary>
    /// Verifies an already-held, direct VC2 JWS without depending on the issuer database.
    /// The policy input MUST come from the caller's own trust configuration, not from
    /// the untrusted credential. A signature does not prove holder control, current
    /// non-revocation, identity vetting or business authorization.
    /// </summary>
    internal static IResult Verify([FromBody] VerifyVcdm20CredentialRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);
        var context = request.SubjectContextUri;
        if (string.IsNullOrWhiteSpace(request.Credential) ||
            request.Credential.Length > MaximumJwtLength ||
            string.IsNullOrWhiteSpace(request.TrustedIssuerDid) ||
            request.TrustedIssuerDid.Length > 255 ||
            string.IsNullOrWhiteSpace(request.ExpectedHolderDid) ||
            request.ExpectedHolderDid.Length > 255 ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.ExpectedCredentialType.Length > 128 ||
            context is null || !context.IsAbsoluteUri ||
            context.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(context.UserInfo) ||
            !string.IsNullOrEmpty(context.Fragment) ||
            context.AbsoluteUri.Length > 2048)
        {
            return Results.Problem(title: "Invalid Request",
                detail: "A bounded credential and independently trusted issuer, expected holder, type and HTTPS claim vocabulary are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Only release subject data after exact issuer key/holder/type/context,
        // validFrom/validUntil, strict JWT structure and Ed25519 signature all pass.
        bool verified = Vcdm20JoseCredential.TryVerify(
            request.Credential, request.TrustedIssuerDid, request.ExpectedHolderDid,
            request.ExpectedCredentialType, context, clock.GetUtcNow(), out var subject);
        return verified
            ? Results.Ok(new VerifyVcdm20CredentialResponse("SignedButStatusUnchecked", subject))
            : Results.Ok(new VerifyVcdm20CredentialResponse("Invalid", null));
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
