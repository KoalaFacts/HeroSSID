using HeroSSID.Api.Authentication;
using HeroSSID.Credentials.Vcdm20;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Verifier-owned incident cutoff for independently pinned active or retired
/// VC2 issuers, exposed to authenticated non-.NET relying parties.
/// </summary>
internal static class Vcdm20RetiredIssuerIncidentHttpEndpoint
{
    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/verify-active-and-retired-after-incident",
                VerifyWithStatusAfterCutoff)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyVcdm20ActiveAndRetiredAfterIncident")
            .WithSummary("Require a post-incident issuer-signed VC2 status for active or exact-pinned retired credentials")
            .Produces<VerifyVcdm20TrustedIssuersResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    internal static IResult VerifyWithStatusAfterCutoff(
        [FromBody] VerifyVcdm20RetiredIssuerIncidentRequest request,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);
        // First deliver the endpoint contract and real failing HTTP tests.
        // Production verification is deliberately not implemented in this red commit.
        return Results.Ok(new VerifyVcdm20TrustedIssuersResponse("Invalid", null, null));
    }
}

/// <summary>Only the independently authenticated issuer can publish status; the verifier chooses its trust pins and cutoff.</summary>
public sealed record class VerifyVcdm20RetiredIssuerIncidentRequest
{
    public string? Credential { get; init; }
    public IReadOnlyCollection<string>? ActiveIssuerDids { get; init; }
    public IReadOnlyCollection<Vcdm20RetiredCredentialPin>? RetiredCredentialPins { get; init; }
    public string? ExpectedHolderDid { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public string? RevocationSnapshot { get; init; }
    public DateTimeOffset? MinimumObservedAt { get; init; }
}
