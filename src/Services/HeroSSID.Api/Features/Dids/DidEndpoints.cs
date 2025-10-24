using HeroSSID.Core.TenantManagement;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidResolution;
using Microsoft.AspNetCore.Mvc;

namespace HeroSSID.Api.Features.Dids;

/// <summary>
/// DID endpoints for User Story 1 - REST API
/// </summary>
#pragma warning disable CA1515 // Public static class for endpoint registration
public static class DidEndpoints
#pragma warning restore CA1515
{
    /// <summary>
    /// Maps DID endpoints to the application
    /// </summary>
    public static void MapDidEndpoints(this IEndpointRouteBuilder app)
    {
        var dids = app.MapGroup("/api/v1/dids")
            .WithTags("DIDs")
            .WithOpenApi();

        // POST /api/v1/dids - Create a new DID
        dids.MapPost("/", CreateDid)
            .WithName("CreateDid")
            .WithSummary("Create a new DID")
            .Produces<CreateDidResponse>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        // GET /api/v1/dids/{did} - Resolve a DID
        dids.MapGet("/{did}", ResolveDid)
            .WithName("ResolveDid")
            .WithSummary("Resolve a DID to its DID Document")
            .Produces<object>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
    }

    private static async Task<IResult> CreateDid(
        [FromBody] CreateDidRequest request,
        [FromServices] IDidCreationService didCreationService,
        [FromServices] IDidResolutionService didResolutionService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        try
        {
            // Validate request
            if (string.IsNullOrWhiteSpace(request.Method))
            {
                return Results.Problem(
                    title: "Invalid Request",
                    detail: "Method is required",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            if (string.IsNullOrWhiteSpace(request.KeyType))
            {
                return Results.Problem(
                    title: "Invalid Request",
                    detail: "KeyType is required",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            // Only support did:key for now
            if (!request.Method.Equals("did:key", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Problem(
                    title: "Unsupported DID Method",
                    detail: $"DID method '{request.Method}' is not supported. Only 'did:key' is currently supported.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            // Only support Ed25519 for now
            if (!request.KeyType.Equals("Ed25519", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Problem(
                    title: "Unsupported Key Type",
                    detail: $"Key type '{request.KeyType}' is not supported. Only 'Ed25519' is currently supported.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            logger.LogInformation(
                "Creating DID with method {Method} and key type {KeyType} for tenant {TenantId}",
                request.Method,
                request.KeyType,
                tenantContext.GetCurrentTenantId()
            );

            // Create the DID
            var result = await didCreationService.CreateDidAsync(cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrEmpty(result.DidIdentifier))
            {
                logger.LogError(
                    "Failed to create DID for tenant {TenantId}",
                    tenantContext.GetCurrentTenantId()
                );

                return Results.Problem(
                    title: "DID Creation Failed",
                    detail: "An error occurred while creating the DID",
                    statusCode: StatusCodes.Status500InternalServerError
                );
            }

            // Resolve the DID to get the full DID Document
            var resolveResult = await didResolutionService.ResolveAsync(result.DidIdentifier, cancellationToken).ConfigureAwait(false);

            if (resolveResult.DidDocument == null)
            {
                logger.LogError(
                    "Created DID {Did} but failed to resolve it for tenant {TenantId}",
                    result.DidIdentifier,
                    tenantContext.GetCurrentTenantId()
                );

                return Results.Problem(
                    title: "DID Resolution Failed",
                    detail: "DID was created but could not be resolved",
                    statusCode: StatusCodes.Status500InternalServerError
                );
            }

            logger.LogInformation(
                "Successfully created DID {Did} for tenant {TenantId}",
                result.DidIdentifier,
                tenantContext.GetCurrentTenantId()
            );

            var response = new CreateDidResponse
            {
                Did = result.DidIdentifier,
                DidDocument = resolveResult.DidDocument
            };

            return Results.Created($"/api/v1/dids/{Uri.EscapeDataString(result.DidIdentifier)}", response);
        }
#pragma warning disable CA1031 // Catch specific exceptions - endpoints need to handle all exceptions
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger.LogError(
                ex,
                "Unexpected error creating DID for tenant {TenantId}",
                tenantContext.GetCurrentTenantId()
            );

            return Results.Problem(
                title: "Internal Server Error",
                detail: "An unexpected error occurred while creating the DID",
                statusCode: StatusCodes.Status500InternalServerError
            );
        }
    }

    private static async Task<IResult> ResolveDid(
        string did,
        [FromServices] IDidResolutionService didResolutionService,
        [FromServices] ITenantContext tenantContext,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        try
        {
            // Validate DID format
            if (string.IsNullOrWhiteSpace(did))
            {
                return Results.Problem(
                    title: "Invalid DID",
                    detail: "DID identifier is required",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            if (!did.StartsWith("did:", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Problem(
                    title: "Invalid DID Format",
                    detail: "DID must start with 'did:'",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            logger.LogInformation(
                "Resolving DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );

            // Resolve the DID
            var result = await didResolutionService.ResolveAsync(did, cancellationToken).ConfigureAwait(false);

            if (result.DidDocument == null)
            {
                logger.LogWarning(
                    "Failed to resolve DID {Did} for tenant {TenantId}",
                    did,
                    tenantContext.GetCurrentTenantId()
                );

                return Results.Problem(
                    title: "DID Not Found",
                    detail: $"DID '{did}' could not be resolved",
                    statusCode: StatusCodes.Status404NotFound
                );
            }

            logger.LogInformation(
                "Successfully resolved DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );

            return Results.Ok(result.DidDocument);
        }
#pragma warning disable CA1031 // Catch specific exceptions - endpoints need to handle all exceptions
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger.LogError(
                ex,
                "Unexpected error resolving DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );

            return Results.Problem(
                title: "Internal Server Error",
                detail: "An unexpected error occurred while resolving the DID",
                statusCode: StatusCodes.Status500InternalServerError
            );
        }
    }
}
