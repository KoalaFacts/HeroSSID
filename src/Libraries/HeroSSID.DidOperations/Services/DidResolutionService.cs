using HeroSSID.Core.Interfaces;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.DidOperations.Services;

/// <summary>
/// Service for resolving Decentralized Identifiers (DIDs) to their DID Documents.
/// Implements W3C DID Core Resolution specification with database backing and caching.
/// Reference: https://www.w3.org/TR/did-core/#did-resolution
/// </summary>
public sealed class DidResolutionService : IDidResolutionService
{
    private readonly HeroDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly DidMethodResolver _didMethodResolver;
    private readonly ILogger<DidResolutionService> _logger;

    // Logging delegates for structured logging
    private static readonly Action<ILogger, string, Exception?> s_logResolvingDid =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(1, "ResolvingDid"),
            "Resolving DID: {DidIdentifier}");

    private static readonly Action<ILogger, string, Exception?> s_logDidNotFound =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(2, "DidNotFound"),
            "DID not found: {DidIdentifier}");

    private static readonly Action<ILogger, string, Exception?> s_logDidResolved =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(3, "DidResolved"),
            "Successfully resolved DID: {DidIdentifier}");

    private static readonly Action<ILogger, string, Exception?> s_logInvalidDid =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(4, "InvalidDid"),
            "Invalid DID format: {DidIdentifier}");

    /// <summary>
    /// Creates a new DidResolutionService
    /// </summary>
    public DidResolutionService(
        HeroDbContext dbContext,
        ITenantContext tenantContext,
        DidMethodResolver didMethodResolver,
        ILogger<DidResolutionService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
        _didMethodResolver = didMethodResolver ?? throw new ArgumentNullException(nameof(didMethodResolver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Resolves a DID to its DID Document.
    /// </summary>
    public async Task<DidResolutionResult> ResolveAsync(string didIdentifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);

        s_logResolvingDid(_logger, didIdentifier, null);

        // Step 1: Validate DID format
        if (!IsValidDidFormat(didIdentifier))
        {
            s_logInvalidDid(_logger, didIdentifier, null);
            return new DidResolutionResult
            {
                DidIdentifier = didIdentifier,
                Metadata = DidResolutionMetadata.CreateError("invalidDid", $"Invalid DID format: {didIdentifier}")
            };
        }

        // Step 2: Check if method is supported
        if (!_didMethodResolver.CanResolveDid(didIdentifier))
        {
            return new DidResolutionResult
            {
                DidIdentifier = didIdentifier,
                Metadata = DidResolutionMetadata.CreateError("methodNotSupported", $"DID method not supported for: {didIdentifier}")
            };
        }

        // Step 3: Retrieve from database
        Guid tenantId = _tenantContext.GetCurrentTenantId();
        DidEntity? didEntity = await _dbContext.Dids
            .AsNoTracking()
            .FirstOrDefaultAsync(
                d => d.DidIdentifier == didIdentifier && d.TenantId == tenantId,
                cancellationToken)
            .ConfigureAwait(false);

        if (didEntity == null)
        {
            s_logDidNotFound(_logger, didIdentifier, null);
            return new DidResolutionResult
            {
                DidIdentifier = didIdentifier,
                Metadata = DidResolutionMetadata.CreateError("notFound", $"DID not found: {didIdentifier}")
            };
        }

        // Step 4: Return resolved DID Document
        s_logDidResolved(_logger, didIdentifier, null);
        return new DidResolutionResult
        {
            DidIdentifier = didIdentifier,
            DidDocument = didEntity.DidDocumentJson,
            Metadata = DidResolutionMetadata.CreateSuccess()
        };
    }

    /// <summary>
    /// Retrieves a DID by its database ID.
    /// </summary>
    public async Task<DidRetrievalResult?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        Guid tenantId = _tenantContext.GetCurrentTenantId();

        DidEntity? didEntity = await _dbContext.Dids
            .AsNoTracking()
            .FirstOrDefaultAsync(
                d => d.Id == id && d.TenantId == tenantId,
                cancellationToken)
            .ConfigureAwait(false);

        if (didEntity == null)
        {
            return null;
        }

        return new DidRetrievalResult
        {
            Id = didEntity.Id,
            TenantId = didEntity.TenantId,
            DidIdentifier = didEntity.DidIdentifier,
            PublicKey = didEntity.PublicKeyEd25519,
            DidDocumentJson = didEntity.DidDocumentJson,
            Status = didEntity.Status,
            CreatedAt = didEntity.CreatedAt
        };
    }

    /// <summary>
    /// Checks if a DID exists in the database.
    /// </summary>
    public async Task<bool> ExistsAsync(string didIdentifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);

        Guid tenantId = _tenantContext.GetCurrentTenantId();

        return await _dbContext.Dids
            .AsNoTracking()
            .AnyAsync(
                d => d.DidIdentifier == didIdentifier && d.TenantId == tenantId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Validates basic DID format according to W3C spec.
    /// Format: did:method:method-specific-id
    /// </summary>
    private static bool IsValidDidFormat(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            return false;
        }

        // Must start with "did:"
        if (!did.StartsWith("did:", StringComparison.Ordinal))
        {
            return false;
        }

        // Must have at least 3 parts separated by colons
        string[] parts = did.Split(':');
        if (parts.Length < 3)
        {
            return false;
        }

        // Method name and method-specific-id must not be empty
        return !string.IsNullOrWhiteSpace(parts[1]) && !string.IsNullOrWhiteSpace(parts[2]);
    }
}
