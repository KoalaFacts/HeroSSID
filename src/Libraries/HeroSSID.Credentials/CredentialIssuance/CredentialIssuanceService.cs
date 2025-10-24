using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.Credentials.CredentialIssuance;

/// <summary>
/// Service for issuing W3C Verifiable Credentials in JWT format (JWT-VC)
/// Implements multi-tenant isolation, rate limiting, and Ed25519 signing
/// </summary>
public sealed class CredentialIssuanceService : ICredentialIssuanceService
{
    // T050: Structured logging with high-performance LoggerMessage delegates
    // SECURITY: No sensitive data (credentials, private keys) in logs - only metadata
    private static readonly Action<ILogger, Guid, Guid, string, Exception?> _logCredentialIssued =
        LoggerMessage.Define<Guid, Guid, string>(
            LogLevel.Information,
            new EventId(1, nameof(IssueCredentialAsync)),
            "Credential issued successfully: TenantId={TenantId}, IssuerDidId={IssuerDidId}, CredentialType={CredentialType}");

    private static readonly Action<ILogger, Guid, Guid, Guid, Guid, Exception?> _logCrossTenantIssuance =
        LoggerMessage.Define<Guid, Guid, Guid, Guid>(
            LogLevel.Warning,
            new EventId(2, nameof(IssueCredentialAsync)),
            "Cross-tenant credential issued: IssuerTenant={IssuerTenant}, HolderTenant={HolderTenant}, IssuerDid={IssuerDid}, HolderDid={HolderDid}");

    private static readonly Action<ILogger, Guid, string, Exception?> _logRateLimitExceeded =
        LoggerMessage.Define<Guid, string>(
            LogLevel.Warning,
            new EventId(3, nameof(IssueCredentialAsync)),
            "Rate limit exceeded: TenantId={TenantId}, OperationType={OperationType}");

    private static readonly Action<ILogger, Guid, Guid, Exception?> _logIssuanceFailed =
        LoggerMessage.Define<Guid, Guid>(
            LogLevel.Error,
            new EventId(4, nameof(IssueCredentialAsync)),
            "Credential issuance failed: TenantId={TenantId}, IssuerDidId={IssuerDidId}");

    private static readonly string[] W3cVcContext = new[] { "https://www.w3.org/2018/credentials/v1" };

    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _keyEncryptionService;
    private readonly IRateLimiter _rateLimiter;
    private readonly ILogger<CredentialIssuanceService>? _logger;

    /// <summary>
    /// Initializes a new instance of the CredentialIssuanceService
    /// </summary>
    /// <param name="dbContext">Database context for DID and credential storage</param>
    /// <param name="keyEncryptionService">Service for decrypting private keys</param>
    /// <param name="rateLimiter">Rate limiter for preventing resource exhaustion</param>
    /// <param name="logger">Optional logger for structured logging</param>
    /// <exception cref="ArgumentNullException">Thrown when required dependencies are null</exception>
    public CredentialIssuanceService(
        HeroDbContext dbContext,
        IKeyEncryptionService keyEncryptionService,
        IRateLimiter rateLimiter,
        ILogger<CredentialIssuanceService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(keyEncryptionService);
        ArgumentNullException.ThrowIfNull(rateLimiter);

        _dbContext = dbContext;
        _keyEncryptionService = keyEncryptionService;
        _rateLimiter = rateLimiter;
        _logger = logger;
    }

    /// <summary>
    /// Issues a W3C Verifiable Credential in JWT format (JWT-VC)
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation</param>
    /// <param name="issuerDidId">ID of the issuer DID</param>
    /// <param name="holderDidId">ID of the holder DID</param>
    /// <param name="credentialType">Type of credential (e.g., "UniversityDegreeCredential")</param>
    /// <param name="credentialSubject">Claims to include in the credential</param>
    /// <param name="expirationDate">Optional expiration date for the credential</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>JWT-formatted verifiable credential (JWT-VC)</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when DIDs are not found or invalid</exception>
    public async Task<string> IssueCredentialAsync(
        ITenantContext tenantContext,
        Guid issuerDidId,
        Guid holderDidId,
        string credentialType,
        Dictionary<string, object> credentialSubject,
        DateTimeOffset? expirationDate = null,
        CancellationToken cancellationToken = default)
    {
        // T014: Rate limiting and input validation
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(credentialSubject);

        // SECURITY: Validate credential type is not empty
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialType, nameof(credentialType));

        // SECURITY: Validate credential subject is not empty
        if (credentialSubject.Count == 0)
        {
            throw new ArgumentException("Credential subject cannot be empty. At least one claim must be provided.", nameof(credentialSubject));
        }

        // SECURITY: Validate credential subject payload size (prevent DoS attacks)
        const int MaxPayloadSizeBytes = 100 * 1024; // 100KB limit
        var payloadJson = System.Text.Json.JsonSerializer.Serialize(credentialSubject);
        var payloadSizeBytes = System.Text.Encoding.UTF8.GetByteCount(payloadJson);

        if (payloadSizeBytes > MaxPayloadSizeBytes)
        {
            throw new ArgumentException(
                $"Credential subject payload exceeds maximum size of {MaxPayloadSizeBytes / 1024}KB. Current size: {payloadSizeBytes / 1024}KB",
                nameof(credentialSubject));
        }

        var currentTenantId = tenantContext.GetCurrentTenantId();

        // T050: Wrap in try-catch for comprehensive error logging
        try
        {
            return await IssueCredentialInternalAsync(
                currentTenantId,
                issuerDidId,
                holderDidId,
                credentialType,
                credentialSubject,
                expirationDate,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not ArgumentNullException and not ArgumentException and not InvalidOperationException)
        {
            // T050: Log unexpected errors with context
            if (_logger != null)
            {
                _logIssuanceFailed(_logger, currentTenantId, issuerDidId, ex);
            }
            throw;
        }
    }

    private async Task<string> IssueCredentialInternalAsync(
        Guid currentTenantId,
        Guid issuerDidId,
        Guid holderDidId,
        string credentialType,
        Dictionary<string, object> credentialSubject,
        DateTimeOffset? expirationDate,
        CancellationToken cancellationToken)
    {

        // Check rate limit
        var isAllowed = await _rateLimiter.IsAllowedAsync(currentTenantId, "CREDENTIAL_ISSUE", cancellationToken).ConfigureAwait(false);
        if (!isAllowed)
        {
            // T050: Log rate limit exceeded event
            if (_logger != null)
            {
                _logRateLimitExceeded(_logger, currentTenantId, "CREDENTIAL_ISSUE", null);
            }
            throw new InvalidOperationException("Rate limit exceeded for credential issuance");
        }

        // T016: Tenant isolation - validate issuer DID belongs to current tenant
        var issuerDid = await _dbContext.Dids
            .Where(d => d.Id == issuerDidId && d.TenantId == currentTenantId)
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        if (issuerDid == null)
        {
            throw new ArgumentException($"Issuer DID not found or does not belong to tenant", nameof(issuerDidId));
        }

        if (issuerDid.Status == "deactivated")
        {
            throw new ArgumentException("Issuer DID is deactivated", nameof(issuerDidId));
        }

        // T016: Validate holder DID exists (SECURITY: enforce tenant isolation)
        // NOTE: Holder can be from a different tenant (cross-tenant credential issuance is allowed)
        // but we log this for audit purposes
        var holderDid = await _dbContext.Dids
            .Where(d => d.Id == holderDidId)
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        if (holderDid == null)
        {
            throw new ArgumentException("Holder DID not found", nameof(holderDidId));
        }

        // SECURITY: Log cross-tenant credential issuance for audit
        if (holderDid.TenantId != currentTenantId)
        {
            if (_logger != null)
            {
                _logCrossTenantIssuance(_logger, currentTenantId, holderDid.TenantId, issuerDidId, holderDidId, null);
            }
        }

        // T018: Create JWT-VC with real Ed25519 signing
        var jwtVc = CreateJwtVc(issuerDid, holderDid, credentialType, credentialSubject, expirationDate);

        // T020: Database persistence
        var credential = new Data.Entities.VerifiableCredentialEntity
        {
            Id = Guid.NewGuid(),
            TenantId = currentTenantId,
            IssuerDidId = issuerDidId,
            HolderDidId = holderDidId,
            CredentialType = credentialType,
            CredentialJwt = jwtVc,
            Status = "active",
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expirationDate
        };

        _dbContext.VerifiableCredentials.Add(credential);
        await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        // Record operation for rate limiting
        await _rateLimiter.RecordOperationAsync(currentTenantId, "CREDENTIAL_ISSUE", cancellationToken).ConfigureAwait(false);

        if (_logger != null)
        {
            _logCredentialIssued(_logger, currentTenantId, issuerDidId, credentialType, null);
        }

        return jwtVc;
    }

    private string CreateJwtVc(
        Data.Entities.DidEntity issuerDid,
        Data.Entities.DidEntity holderDid,
        string credentialType,
        Dictionary<string, object> credentialSubject,
        DateTimeOffset? expirationDate)
    {
        // T018: JWT-VC creation with real Ed25519 signing
        // SECURITY: Ensure private key is always cleared, even on exception
        byte[]? privateKeyBytes = null;

        try
        {
            // Decrypt issuer's private key
            privateKeyBytes = _keyEncryptionService.Decrypt(issuerDid.PrivateKeyEd25519Encrypted);

            // Build W3C VC 2.0 JWT header
            var header = System.Text.Json.JsonSerializer.Serialize(new
            {
                typ = "vc+jwt",
                alg = "EdDSA"
            });

            // Build W3C VC 2.0 JWT payload
            var issuedAt = DateTimeOffset.UtcNow;
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                iss = issuerDid.DidIdentifier,
                sub = holderDid.DidIdentifier,
                iat = issuedAt.ToUnixTimeSeconds(),
                exp = expirationDate?.ToUnixTimeSeconds(),
                vc = new
                {
                    context = W3cVcContext,
                    type = new[] { "VerifiableCredential", credentialType },
                    credentialSubject
                }
            });

            // Sign the JWT with Ed25519
            var jwt = Utilities.Ed25519JwtSigner.CreateSignedJwt(header, payload, privateKeyBytes);

            return jwt;
        }
        finally
        {
            // SECURITY: Clear decrypted private key from memory (even if exception occurred)
            if (privateKeyBytes != null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(privateKeyBytes);
            }
        }
    }
}
