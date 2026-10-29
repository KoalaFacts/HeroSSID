using HeroSSID.Api.Authentication;
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
            .RequireAuthorization(OperationScopes.DidManage)
            .WithTags("DIDs");

        // Read-only, explicitly opted-in DID:key compatibility profile.
        // The existing resolution path continues to return persisted JSON.
        dids.MapGet("/{did}/canonical", ResolveCanonicalDidKey)
            .WithName("ResolveCanonicalDidKey")
            .WithSummary("Derive a current did:key document from the stored public key without rewriting the database")
            .Produces<object>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound);

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

    private static async Task<IResult> ResolveCanonicalDidKey(
        string did,
        [FromServices] ICanonicalDidResolutionService didResolutionService,
        CancellationToken cancellationToken)
    {
        // Treat unsupported/malformed identifiers and mismatched stored keys
        // as unavailable; no credential, tenant or key information is disclosed.
        if (string.IsNullOrWhiteSpace(did) || did.Length > 256 ||
            !did.StartsWith("did:key:", StringComparison.Ordinal))
        {
            return Results.NotFound();
        }

        var result = await didResolutionService.ResolveCanonicalDidKeyAsync(
            did, cancellationToken).ConfigureAwait(false);
        if (result.DidDocument is null)
        {
            return Results.NotFound();
        }

        using var document = System.Text.Json.JsonDocument.Parse(result.DidDocument);
        return Results.Ok(document.RootElement.Clone());
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

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                "Creating DID with method {Method} and key type {KeyType} for tenant {TenantId}",
                request.Method,
                request.KeyType,
                tenantContext.GetCurrentTenantId()
            );
            }

            // Create the DID
            var result = await didCreationService.CreateDidAsync(cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrEmpty(result.DidIdentifier))
            {
                if (logger.IsEnabled(LogLevel.Error))
                {
                    logger.LogError(
                    "Failed to create DID for tenant {TenantId}",
                    tenantContext.GetCurrentTenantId()
                );
                }

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
                if (logger.IsEnabled(LogLevel.Error))
                {
                    logger.LogError(
                    "Created DID {Did} but failed to resolve it for tenant {TenantId}",
                    result.DidIdentifier,
                    tenantContext.GetCurrentTenantId()
                );
                }

                return Results.Problem(
                    title: "DID Resolution Failed",
                    detail: "DID was created but could not be resolved",
                    statusCode: StatusCodes.Status500InternalServerError
                );
            }

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                "Successfully created DID {Did} for tenant {TenantId}",
                result.DidIdentifier,
                tenantContext.GetCurrentTenantId()
            );
            }

            // Parse the DID Document JSON string to an object before returning
            var didDocumentObject = System.Text.Json.JsonSerializer.Deserialize<object>(resolveResult.DidDocument!)
                ?? throw new InvalidOperationException("Failed to deserialize DID Document");

            var response = new CreateDidResponse
            {
                Did = result.DidIdentifier,
                DidDocument = didDocumentObject
            };

            return Results.Created($"/api/v1/dids/{Uri.EscapeDataString(result.DidIdentifier)}", response);
        }
#pragma warning disable CA1031 // Catch specific exceptions - endpoints need to handle all exceptions
        catch (Exception ex)
#pragma warning restore CA1031
        {
            if (logger.IsEnabled(LogLevel.Error))
            {
                logger.LogError(
                ex,
                "Unexpected error creating DID for tenant {TenantId}",
                tenantContext.GetCurrentTenantId()
            );
            }

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

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                "Resolving DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );
            }

            // Resolve the DID
            var result = await didResolutionService.ResolveAsync(did, cancellationToken).ConfigureAwait(false);

            if (result.DidDocument == null)
            {
                if (logger.IsEnabled(LogLevel.Warning))
                {
                    logger.LogWarning(
                    "Failed to resolve DID {Did} for tenant {TenantId}",
                    did,
                    tenantContext.GetCurrentTenantId()
                );
                }

                return Results.Problem(
                    title: "DID Not Found",
                    detail: $"DID '{did}' could not be resolved",
                    statusCode: StatusCodes.Status404NotFound
                );
            }

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                "Successfully resolved DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );
            }

            // Parse the DID Document JSON string to an object before returning
            // This prevents double-encoding (the string would otherwise be serialized as a JSON string)
            var didDocumentObject = System.Text.Json.JsonSerializer.Deserialize<object>(result.DidDocument)
                ?? throw new InvalidOperationException("Failed to deserialize DID Document");
            return Results.Ok(didDocumentObject);
        }
#pragma warning disable CA1031 // Catch specific exceptions - endpoints need to handle all exceptions
        catch (Exception ex)
#pragma warning restore CA1031
        {
            if (logger.IsEnabled(LogLevel.Error))
            {
                logger.LogError(
                ex,
                "Unexpected error resolving DID {Did} for tenant {TenantId}",
                did,
                tenantContext.GetCurrentTenantId()
            );
            }

            return Results.Problem(
                title: "Internal Server Error",
                detail: "An unexpected error occurred while resolving the DID",
                statusCode: StatusCodes.Status500InternalServerError
            );
        }
    }
}
