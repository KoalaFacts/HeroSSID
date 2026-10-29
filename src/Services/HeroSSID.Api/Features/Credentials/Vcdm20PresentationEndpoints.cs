using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>Authenticated, verifier-owned single-use VC2 presentation boundary.</summary>
internal static class Vcdm20PresentationEndpoints
{
    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/vcdm20/presentation-challenge", Issue)
            .RequireAuthorization("credential:verify");
        credentials.MapPost("/vcdm20/verify-presentation", Verify)
            .RequireAuthorization("credential:verify");
    }

    internal static IResult Issue(
        [FromBody] IssueVcdm20PresentationChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
        => Results.Problem(statusCode: StatusCodes.Status501NotImplemented);

    internal static IResult Verify(
        [FromBody] VerifyVcdm20PresentationRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
        => Results.Ok(new VerifyVcdm20PresentationResponse("Invalid", null));
}

/// <summary>Only the verifier chooses and retains trusted issuer and challenge audience.</summary>
public sealed class IssueVcdm20PresentationChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>Verifiers must sign this challenge with an independently held verifier key.</summary>
public sealed record IssueVcdm20PresentationChallengeResponse(
    string Audience, string Nonce, string TrustedIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Caller pins claim vocabulary and type; the server retains issuer policy.</summary>
public sealed class VerifyVcdm20PresentationRequest
{
    public string? Presentation { get; init; }
    public string? RevocationSnapshot { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>Only SignedNotListed returns verified claims; it never grants authorization.</summary>
public sealed record VerifyVcdm20PresentationResponse(string Status, JsonElement? VerifiedSubject);
