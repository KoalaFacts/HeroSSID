using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>REST credential issuance and verification endpoints.</summary>
public static class CredentialEndpoints
{
    public static void MapCredentialEndpoints(this IEndpointRouteBuilder app)
    {
        var credentials = app.MapGroup("/api/v1/credentials")
            .WithTags("Credentials");

        credentials.MapPost("/issue", IssueAsync)
            .RequireAuthorization(CredentialIssueRequirement.PolicyName)
            .WithName("IssueCredential")
            .WithSummary("Issue a JWT verifiable credential")
            .Produces<IssueCredentialResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        credentials.MapPost("/verify", VerifyAsync)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyCredential")
            .WithSummary("Verify a JWT verifiable credential")
            .Produces<VerifyCredentialResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        credentials.MapPost("/revocation-snapshot", ExportRevocationSnapshotAsync)
            .RequireAuthorization(OperationScopes.CredentialRevoke)
            .WithName("ExportIssuerRevocationSnapshot")
            .WithSummary("Export a short-lived issuer-signed revocation snapshot (HeroSSID profile)")
            .Produces<ExportRevocationSnapshotResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        credentials.MapPost("/revoke", RevokeAsync)
            .RequireAuthorization(OperationScopes.CredentialRevoke)
            .WithName("RevokeCredential")
            .WithSummary("Revoke an exact, locally issued credential with issuer revocation scope")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
    }

    internal static async Task<IResult> IssueAsync(
        [FromBody] IssueCredentialRequest request,
        [FromServices] ICredentialDidLookup didLookup,
        [FromServices] ICredentialIssuanceService issuanceService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.IssuerDid) ||
            string.IsNullOrWhiteSpace(request.HolderDid) ||
            string.IsNullOrWhiteSpace(request.CredentialType) ||
            request.Claims is null || request.Claims.Count == 0)
        {
            return InvalidRequest("IssuerDid, HolderDid, CredentialType and non-empty Claims are required.");
        }

        try
        {
            // Issuance scope grants access to this tenant's issuers. Per-client DID grants are future work.
            var issuerId = await didLookup.FindIssuerAsync(
                request.IssuerDid, tenantContext.GetCurrentTenantId(), cancellationToken).ConfigureAwait(false);
            var holderId = await didLookup.FindHolderAsync(request.HolderDid, cancellationToken).ConfigureAwait(false);
            if (issuerId is null || holderId is null)
            {
                return InvalidRequest("The issuer or holder DID is unavailable for credential issuance.");
            }

            var credential = await issuanceService.IssueCredentialAsync(
                tenantContext, issuerId.Value, holderId.Value, request.CredentialType, request.Claims,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // No credential retrieval route exists, so do not advertise an invented Location URI.
            return Results.Json(new IssueCredentialResponse(credential), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The credential issuance request is invalid.");
        }
        catch (InvalidOperationException exception) when (exception.Message == "Rate limit exceeded for credential issuance")
        {
            return RateLimitExceeded();
        }
#pragma warning disable CA1031 // Translate unexpected endpoint failures without exposing credentials or internal details.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "Credential issuance failed");
            return InternalError();
        }
    }

    internal static async Task<IResult> VerifyAsync(
        [FromBody] VerifyCredentialRequest request,
        [FromServices] ICredentialVerificationService verificationService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Credential))
        {
            return InvalidRequest("Credential is required.");
        }

        try
        {
            var result = await verificationService.VerifyCredentialAsync(
                tenantContext, request.Credential, cancellationToken).ConfigureAwait(false);
            if (result.Status == VerificationStatus.MalformedJwt)
            {
                return InvalidRequest("The credential is not a supported JWT verifiable credential.");
            }

            if (!result.IsValid)
            {
                // The library can return parsed claims before checking the signature. Do not expose them as verified identity.
                return Results.Ok(new VerifyCredentialResponse(false, null, null));
            }

            // Only decode the exact token that the service has successfully verified.
            using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(request.Credential));
            var holderDid = payload.RootElement.TryGetProperty("sub", out var subject) && subject.ValueKind == JsonValueKind.String
                ? subject.GetString()
                : null;
            return Results.Ok(new VerifyCredentialResponse(true, result.IssuerDid, holderDid));
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The credential verification request is invalid.");
        }
        catch (InvalidOperationException exception) when (exception.Message == "Rate limit exceeded for credential verification")
        {
            return RateLimitExceeded();
        }
#pragma warning disable CA1031 // Translate unexpected endpoint failures without exposing credentials or internal details.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "Credential verification failed");
            return InternalError();
        }
    }

    internal static async Task<IResult> RevokeAsync(
        [FromBody] RevokeCredentialRequest request,
        [FromServices] IIssuedCredentialRevocationService revocationService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Credential))
        {
            return InvalidRequest("Credential is required.");
        }

        try
        {
            var revoked = await revocationService.RevokeAsync(
                tenantContext, request.Credential, cancellationToken).ConfigureAwait(false);
            // Never distinguish a nonexistent credential from one issued by another tenant.
            return revoked ? Results.NoContent() : Results.NotFound();
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The credential revocation request is invalid.");
        }
        catch (InvalidOperationException exception) when (exception.Message == "Rate limit exceeded for credential revocation")
        {
            return RateLimitExceeded();
        }
#pragma warning disable CA1031 // Translate unexpected failures without leaking stored credential data.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "Credential revocation failed");
            return InternalError();
        }
    }

    internal static async Task<IResult> ExportRevocationSnapshotAsync(
        [FromBody] ExportRevocationSnapshotRequest request,
        [FromServices] IssuerRevocationSnapshotService exportService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.IssuerDid) ||
            request.IssuerDid.Length > 255 ||
            !request.IssuerDid.StartsWith("did:key:", StringComparison.Ordinal))
        {
            return InvalidRequest("A did:key issuer DID is required.");
        }

        try
        {
            var snapshot = await exportService.ExportAsync(
                tenantContext, request.IssuerDid, cancellationToken).ConfigureAwait(false);
            return snapshot is null ? Results.NotFound() : Results.Ok(new ExportRevocationSnapshotResponse(snapshot));
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The revocation snapshot export request is invalid.");
        }
        catch (InvalidOperationException exception) when (exception.Message == IssuerRevocationSnapshotService.RateLimitError)
        {
            return RateLimitExceeded();
        }
        catch (InvalidOperationException exception) when (exception.Message == IssuerRevocationSnapshotService.LimitError)
        {
            return Results.Problem(
                title: "Snapshot Capacity Exceeded",
                detail: "The complete revoked set exceeds the maximum supported export. No partial snapshot was signed.",
                statusCode: StatusCodes.Status409Conflict);
        }
#pragma warning disable CA1031 // Fail closed on unexpected export errors without leaking signing keys or stored credentials.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "Issuer revocation snapshot export failed");
            return InternalError();
        }
    }

    private static IResult InvalidRequest(string detail) => Results.Problem(
        title: "Invalid Request", detail: detail, statusCode: StatusCodes.Status400BadRequest);

    private static IResult RateLimitExceeded() => Results.Problem(
        title: "Too Many Requests", detail: "The credential operation rate limit was exceeded.",
        statusCode: StatusCodes.Status429TooManyRequests);

    private static IResult InternalError() => Results.Problem(
        title: "Internal Server Error", detail: "An unexpected error occurred during the credential operation.",
        statusCode: StatusCodes.Status500InternalServerError);
}
