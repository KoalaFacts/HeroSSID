using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Service for verifying W3C Verifiable Credentials in JWT format (JWT-VC)
/// Implements Ed25519 signature verification, expiration checking, and issuer validation
/// </summary>
public sealed class CredentialVerificationService : ICredentialVerificationService
{
    // JWT claim names as constants to avoid magic strings
    private const string IssuerClaim = "iss";
    private const string ExpirationClaim = "exp";
    private const string VerifiableCredentialClaim = "vc";
    private const string CredentialSubjectClaim = "credentialSubject";
    private const string TypeClaim = "typ";
    private const string AlgorithmClaim = "alg";
    private const string ExpectedType = "vc+jwt";
    private const string ExpectedAlgorithm = "EdDSA";
    private const string RateLimitOperationType = "CREDENTIAL_VERIFY";

    // Security limits
    private const int MaxJwtSizeBytes = 1_000_000; // 1MB limit to prevent DoS
    private const long MinValidTimestamp = 0; // Unix epoch
    private const long MaxValidTimestamp = 253402300800; // Year 10000 limit
    private const int MaxCredentialSubjectSizeBytes = 100_000; // 100KB limit for credential subject

    private static readonly Action<ILogger, string, Exception?> _logCredentialVerified =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(1, nameof(VerifyCredentialAsync)),
            "Credential verified: Status={Status}");

    private static readonly Action<ILogger, string, Exception?> _logVerificationFailed =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(2, nameof(VerifyCredentialAsync)),
            "Credential verification failed: Status={Status}");

    private static readonly Action<ILogger, Guid, Exception?> _logRateLimitExceeded =
        LoggerMessage.Define<Guid>(
            LogLevel.Warning,
            new EventId(3, nameof(VerifyCredentialAsync)),
            "Rate limit exceeded for credential verification (TenantId: {TenantId})");

    private static readonly Action<ILogger, Exception?> _logJwtHeaderParseFailed =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(4, nameof(VerifyCredentialAsync)),
            "Failed to parse JWT header");

    private static readonly Action<ILogger, Exception?> _logJwtPayloadParseFailed =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(5, nameof(VerifyCredentialAsync)),
            "Failed to parse JWT payload");

    private static readonly Action<ILogger, string, Guid, Exception?> _logIssuerNotFound =
        LoggerMessage.Define<string, Guid>(
            LogLevel.Warning,
            new EventId(6, nameof(VerifyCredentialAsync)),
            "Issuer DID not found: {IssuerDid}, TenantId: {TenantId}");

    private static readonly Action<ILogger, string, Exception?> _logSignatureVerificationFailed =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(7, nameof(VerifyCredentialAsync)),
            "Signature verification failed for issuer: {IssuerDid}");

    private static readonly Action<ILogger, Guid, Exception?> _logRevokedCredentialAttempt =
        LoggerMessage.Define<Guid>(
            LogLevel.Warning,
            new EventId(8, nameof(VerifyCredentialAsync)),
            "Revoked credential verification attempted: CredentialId={CredentialId}");

    private static readonly Action<ILogger, string, Exception?> _logDeactivatedIssuerAttempt =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(9, nameof(VerifyCredentialAsync)),
            "Verification attempted with deactivated issuer DID: {IssuerDid}");

    private readonly HeroDbContext _dbContext;
    private readonly IRateLimiter _rateLimiter;
    private readonly ILogger<CredentialVerificationService>? _logger;

    /// <summary>
    /// Initializes a new instance of the CredentialVerificationService
    /// </summary>
    /// <param name="dbContext">Database context for DID lookup</param>
    /// <param name="rateLimiter">Rate limiter for DoS protection</param>
    /// <param name="logger">Optional logger for structured logging</param>
    /// <exception cref="ArgumentNullException">Thrown when required dependencies are null</exception>
    public CredentialVerificationService(
        HeroDbContext dbContext,
        IRateLimiter rateLimiter,
        ILogger<CredentialVerificationService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(rateLimiter);

        _dbContext = dbContext;
        _rateLimiter = rateLimiter;
        _logger = logger;
    }

    /// <summary>
    /// Verifies the cryptographic signature and validity of a JWT-VC credential
    /// </summary>
    /// <param name="tenantContext">Tenant context for multi-tenant isolation (REQUIRED)</param>
    /// <param name="credentialJwt">JWT-VC string to verify</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Structured verification result with status code and details</returns>
    /// <exception cref="ArgumentNullException">Thrown when tenantContext is null</exception>
    /// <exception cref="ArgumentException">Thrown when credentialJwt is null or empty</exception>
    public async Task<CredentialVerificationResult> VerifyCredentialAsync(
        ITenantContext tenantContext,
        string credentialJwt,
        CancellationToken cancellationToken = default)
    {
        // T023: Input validation
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (string.IsNullOrWhiteSpace(credentialJwt))
        {
            throw new ArgumentException("Credential JWT cannot be null or empty", nameof(credentialJwt));
        }

        // SECURITY: Prevent DoS attacks via extremely large JWTs
        if (credentialJwt.Length > MaxJwtSizeBytes)
        {
            throw new ArgumentException($"JWT size exceeds maximum allowed size of {MaxJwtSizeBytes} bytes", nameof(credentialJwt));
        }

        // Rate limiting check - use tenant ID for proper isolation
        var tenantId = tenantContext.GetCurrentTenantId();
        var isAllowed = await _rateLimiter.IsAllowedAsync(
            tenantId,
            RateLimitOperationType,
            cancellationToken).ConfigureAwait(false);

        if (!isAllowed)
        {
            if (_logger != null)
            {
                _logRateLimitExceeded(_logger, tenantId, null);
            }
            throw new InvalidOperationException("Rate limit exceeded for credential verification");
        }

        // T024: JWT format validation
        var parts = credentialJwt.Split('.');
        if (parts.Length != 3)
        {
            var result = CreateFailedResult(
                VerificationStatus.MalformedJwt,
                "Invalid JWT format");
            LogVerificationFailure(result.Status);
            return result;
        }

        // Validate JWT header
        try
        {
            var headerJson = Ed25519JwtHelper.ExtractHeader(credentialJwt);
            var headerDocument = JsonDocument.Parse(headerJson);

            // SECURITY: Strict header validation to prevent JWT confusion attacks
            if (!headerDocument.RootElement.TryGetProperty(TypeClaim, out var typ) ||
                typ.GetString() != ExpectedType)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "Invalid JWT header type - must be 'vc+jwt'");
                LogVerificationFailure(result.Status);
                return result;
            }

            if (!headerDocument.RootElement.TryGetProperty(AlgorithmClaim, out var alg) ||
                alg.GetString() != ExpectedAlgorithm)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "Invalid JWT algorithm - must be 'EdDSA'");
                LogVerificationFailure(result.Status);
                return result;
            }

            // SECURITY: Reject JWTs with forbidden header claims that enable attacks
            // - 'kid' (key ID) could enable key confusion attacks
            // - 'jwk' (embedded key) could enable key substitution attacks
            // - 'jku' (JWK Set URL) could enable SSRF/key confusion attacks
            // - 'x5u', 'x5c', 'x5t' (X.509 certificate chains) not used in our implementation
            if (headerDocument.RootElement.TryGetProperty("kid", out _) ||
                headerDocument.RootElement.TryGetProperty("jwk", out _) ||
                headerDocument.RootElement.TryGetProperty("jku", out _) ||
                headerDocument.RootElement.TryGetProperty("x5u", out _) ||
                headerDocument.RootElement.TryGetProperty("x5c", out _) ||
                headerDocument.RootElement.TryGetProperty("x5t", out _))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT header contains forbidden claims");
                LogVerificationFailure(result.Status);
                return result;
            }

            // SECURITY: Ensure header only contains expected claims (alg, typ)
            // This prevents injection of unexpected metadata
            var headerPropertyCount = 0;
            foreach (var _ in headerDocument.RootElement.EnumerateObject())
            {
                headerPropertyCount++;
            }

            if (headerPropertyCount != 2)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT header contains unexpected claims");
                LogVerificationFailure(result.Status);
                return result;
            }
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            if (_logger != null)
            {
                _logJwtHeaderParseFailed(_logger, ex);
            }
            var result = CreateFailedResult(
                VerificationStatus.MalformedJwt,
                "Invalid JWT header format");
            LogVerificationFailure(result.Status);
            return result;
        }

        // T025: Parse JWT payload
        string? issuerDid;
        DateTimeOffset? expiresAt;
        Dictionary<string, object>? credentialSubject;

        try
        {
            var payloadJson = Ed25519JwtHelper.ExtractPayload(credentialJwt);
            var payloadDocument = JsonDocument.Parse(payloadJson);

            // Extract issuer DID
            if (!payloadDocument.RootElement.TryGetProperty(IssuerClaim, out var issElement))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT payload missing required issuer claim");
                LogVerificationFailure(result.Status);
                return result;
            }
            issuerDid = issElement.GetString();

            if (string.IsNullOrWhiteSpace(issuerDid))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT issuer claim is empty");
                LogVerificationFailure(result.Status);
                return result;
            }

            // Extract expiration date (optional) with overflow protection
            expiresAt = null;
            if (payloadDocument.RootElement.TryGetProperty(ExpirationClaim, out var expElement))
            {
                // SECURITY: Handle null exp claim gracefully (credentials without expiration are valid)
                if (expElement.ValueKind == JsonValueKind.Null)
                {
                    // Null expiration means credential doesn't expire - this is valid
                    expiresAt = null;
                }
                else if (expElement.TryGetInt64(out var expUnix) &&
                    expUnix >= MinValidTimestamp &&
                    expUnix <= MaxValidTimestamp)
                {
                    expiresAt = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                }
                else
                {
                    var result = CreateFailedResult(
                        VerificationStatus.MalformedJwt,
                        "Invalid expiration timestamp");
                    LogVerificationFailure(result.Status);
                    return result;
                }
            }

            // Extract credential subject (optional) with size validation
            credentialSubject = null;
            if (payloadDocument.RootElement.TryGetProperty(VerifiableCredentialClaim, out var vcElement))
            {
                if (vcElement.TryGetProperty(CredentialSubjectClaim, out var csElement))
                {
                    var csJson = csElement.GetRawText();

                    // SECURITY: Prevent DoS via extremely large credentialSubject
                    if (csJson.Length > MaxCredentialSubjectSizeBytes)
                    {
                        var result = CreateFailedResult(
                            VerificationStatus.MalformedJwt,
                            $"Credential subject exceeds maximum size of {MaxCredentialSubjectSizeBytes} bytes");
                        LogVerificationFailure(result.Status);
                        return result;
                    }

                    // SECURITY: Validate credentialSubject structure
                    // Must be a JSON object, not an array or primitive
                    if (csElement.ValueKind != JsonValueKind.Object)
                    {
                        var result = CreateFailedResult(
                            VerificationStatus.MalformedJwt,
                            "Credential subject must be a JSON object");
                        LogVerificationFailure(result.Status);
                        return result;
                    }

                    credentialSubject = JsonSerializer.Deserialize<Dictionary<string, object>>(csJson);
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            if (_logger != null)
            {
                _logJwtPayloadParseFailed(_logger, ex);
            }
            var result = CreateFailedResult(
                VerificationStatus.MalformedJwt,
                "Invalid JWT payload format");
            LogVerificationFailure(result.Status);
            return result;
        }

        // T026: Check expiration
        if (expiresAt.HasValue && expiresAt.Value <= DateTimeOffset.UtcNow)
        {
            var result = CreateFailedResult(
                VerificationStatus.Expired,
                $"Credential expired at {expiresAt.Value:O}",
                issuerDid,
                expiresAt,
                credentialSubject);
            LogVerificationFailure(result.Status);
            return result;
        }

        // T027: Resolve issuer DID from database with ENFORCED tenant isolation
        // SECURITY: Always filter by tenant ID to prevent cross-tenant access
        var issuerDidEntity = await _dbContext.Dids
            .Where(d => d.DidIdentifier == issuerDid && d.TenantId == tenantId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (issuerDidEntity == null)
        {
            var result = CreateFailedResult(
                VerificationStatus.IssuerNotFound,
                "Issuer DID not found",
                issuerDid,
                expiresAt,
                credentialSubject);
            if (_logger != null)
            {
                _logIssuerNotFound(_logger, issuerDid, tenantId, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // SECURITY: Check if issuer DID is deactivated
        if (issuerDidEntity.Status == "deactivated")
        {
            var result = CreateFailedResult(
                VerificationStatus.IssuerNotFound,
                "Issuer DID is deactivated",
                issuerDid,
                expiresAt,
                credentialSubject);
            if (_logger != null)
            {
                _logDeactivatedIssuerAttempt(_logger, issuerDid, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // T028: Verify Ed25519 signature
        var isSignatureValid = Ed25519JwtHelper.VerifySignedJwt(
            credentialJwt,
            issuerDidEntity.PublicKeyEd25519);

        if (!isSignatureValid)
        {
            var result = CreateFailedResult(
                VerificationStatus.SignatureInvalid,
                "Signature verification failed",
                issuerDid,
                expiresAt,
                credentialSubject);
            if (_logger != null)
            {
                _logSignatureVerificationFailed(_logger, issuerDid, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // T028a: Check credential revocation status
        // SECURITY: Check if credential has been revoked (with tenant isolation)
        var credential = await _dbContext.VerifiableCredentials
            .Where(vc => vc.CredentialJwt == credentialJwt && vc.TenantId == tenantId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (credential?.Status == "revoked")
        {
            var result = CreateFailedResult(
                VerificationStatus.Revoked,
                "Credential has been revoked",
                issuerDid,
                expiresAt,
                credentialSubject);
            if (_logger != null)
            {
                _logRevokedCredentialAttempt(_logger, credential.Id, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // T029: Return successful verification result
        var successResult = new CredentialVerificationResult
        {
            IsValid = true,
            Status = VerificationStatus.Valid,
            ValidationErrors = Array.Empty<string>(),
            IssuerDid = issuerDid,
            ExpiresAt = expiresAt,
            CredentialSubject = credentialSubject
        };

        if (_logger != null)
        {
            _logCredentialVerified(_logger, successResult.Status.ToString(), null);
        }

        return successResult;
    }

    private void LogVerificationFailure(VerificationStatus status)
    {
        if (_logger != null)
        {
            _logVerificationFailed(_logger, status.ToString(), null);
        }
    }

    private static CredentialVerificationResult CreateFailedResult(
        VerificationStatus status,
        string errorMessage,
        string? issuerDid = null,
        DateTimeOffset? expiresAt = null,
        Dictionary<string, object>? credentialSubject = null)
    {
        return new CredentialVerificationResult
        {
            IsValid = false,
            Status = status,
            ValidationErrors = new[] { errorMessage },
            IssuerDid = issuerDid,
            ExpiresAt = expiresAt,
            CredentialSubject = credentialSubject
        };
    }
}
