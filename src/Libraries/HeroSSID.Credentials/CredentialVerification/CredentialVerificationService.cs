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
    public Task<CredentialVerificationResult> VerifyCredentialAsync(
        ITenantContext tenantContext,
        string credentialJwt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        var tenantId = tenantContext.GetCurrentTenantId();
        return VerifyCredentialCoreAsync(tenantId, tenantId, credentialJwt, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CredentialVerificationResult> VerifyCredentialFromIssuerAsync(
        ITenantContext requesterContext,
        Guid issuerTenantId,
        string credentialJwt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requesterContext);
        return VerifyCredentialCoreAsync(requesterContext.GetCurrentTenantId(), issuerTenantId, credentialJwt, cancellationToken);
    }

    private async Task<CredentialVerificationResult> VerifyCredentialCoreAsync(
        Guid requesterTenantId,
        Guid issuerTenantId,
        string credentialJwt,
        CancellationToken cancellationToken)
    {
        if (requesterTenantId == Guid.Empty || issuerTenantId == Guid.Empty)
        {
            throw new ArgumentException("Non-empty requester and issuer tenant identities are required.");
        }

        if (string.IsNullOrWhiteSpace(credentialJwt))
        {
            throw new ArgumentException("Credential JWT cannot be null or empty", nameof(credentialJwt));
        }

        // SECURITY: Prevent DoS attacks via extremely large JWTs
        if (credentialJwt.Length > MaxJwtSizeBytes)
        {
            throw new ArgumentException($"JWT size exceeds maximum allowed size of {MaxJwtSizeBytes} bytes", nameof(credentialJwt));
        }

        // Issuer lookup ownership never grants permission to spend the issuer's request quota.
        var isAllowed = await _rateLimiter.TryAcquireAsync(
            requesterTenantId,
            RateLimitOperationType,
            cancellationToken).ConfigureAwait(false);

        if (!isAllowed)
        {
            if (_logger != null)
            {
                _logRateLimitExceeded(_logger, requesterTenantId, null);
            }
            throw new InvalidOperationException("Rate limit exceeded for credential verification");
        }

        // Atomic admission above charges this requester once, before parsing or signature work.

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
            var headerJson = Ed25519JwtSigner.ExtractHeader(credentialJwt);
            using var headerDocument = JsonDocument.Parse(headerJson);

            if (headerDocument.RootElement.ValueKind != JsonValueKind.Object)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT header must be a JSON object");
                LogVerificationFailure(result.Status);
                return result;
            }

            // SECURITY: Strict header validation to prevent JWT confusion attacks
            if (!headerDocument.RootElement.TryGetProperty(TypeClaim, out var typ) ||
                typ.ValueKind != JsonValueKind.String ||
                typ.GetString() != ExpectedType)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "Invalid JWT header type - must be 'vc+jwt'");
                LogVerificationFailure(result.Status);
                return result;
            }

            if (!headerDocument.RootElement.TryGetProperty(AlgorithmClaim, out var alg) ||
                alg.ValueKind != JsonValueKind.String ||
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
            var payloadJson = Ed25519JwtSigner.ExtractPayload(credentialJwt);
            using var payloadDocument = JsonDocument.Parse(payloadJson);

            if (payloadDocument.RootElement.ValueKind != JsonValueKind.Object)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT payload must be a JSON object");
                LogVerificationFailure(result.Status);
                return result;
            }

            // Extract issuer DID
            if (!payloadDocument.RootElement.TryGetProperty(IssuerClaim, out var issElement))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT payload missing required issuer claim");
                LogVerificationFailure(result.Status);
                return result;
            }
            if (issElement.ValueKind != JsonValueKind.String && issElement.ValueKind != JsonValueKind.Null)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT issuer claim must be a string");
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

            // A genuine issuer signature over arbitrary JWT JSON is not a credential.
            // These untrusted claims are structural hints only until signature verification succeeds.
            if (!StrictJwtReader.TryGetString(payloadDocument.RootElement, "sub", out var holderDid) ||
                holderDid.Length > 2048)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT credential requires a non-empty holder subject");
                LogVerificationFailure(result.Status);
                return result;
            }

            var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!StrictJwtReader.TryGetTimestamp(payloadDocument.RootElement, "iat", out var issuedAt) ||
                issuedAt > nowUnix)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT credential requires a valid, non-future issued-at timestamp");
                LogVerificationFailure(result.Status);
                return result;
            }

            if (payloadDocument.RootElement.TryGetProperty("nbf", out _) &&
                (!StrictJwtReader.TryGetTimestamp(payloadDocument.RootElement, "nbf", out var notBefore) ||
                 notBefore > nowUnix))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT credential not-before timestamp is invalid or in the future");
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
                else if (expElement.ValueKind == JsonValueKind.Number &&
                    expElement.TryGetInt64(out var expUnix) &&
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

            // A supported local vc+jwt must contain a credential type and an object
            // subject. The holder's id, when present, must agree with the JWT sub.
            if (!payloadDocument.RootElement.TryGetProperty(VerifiableCredentialClaim, out var vcElement) ||
                vcElement.ValueKind != JsonValueKind.Object ||
                !HasLocalCredentialTypes(vcElement))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "JWT payload requires a supported verifiable credential type");
                LogVerificationFailure(result.Status);
                return result;
            }

            if (!vcElement.TryGetProperty(CredentialSubjectClaim, out var csElement) ||
                csElement.ValueKind != JsonValueKind.Object)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "Credential subject must be a JSON object");
                LogVerificationFailure(result.Status);
                return result;
            }

            var csJson = csElement.GetRawText();
            if (csJson.Length > MaxCredentialSubjectSizeBytes)
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    $"Credential subject exceeds maximum size of {MaxCredentialSubjectSizeBytes} bytes");
                LogVerificationFailure(result.Status);
                return result;
            }

            if (csElement.TryGetProperty("id", out _) &&
                (!StrictJwtReader.TryGetString(csElement, "id", out var subjectId) ||
                 !string.Equals(subjectId, holderDid, StringComparison.Ordinal)))
            {
                var result = CreateFailedResult(
                    VerificationStatus.MalformedJwt,
                    "Credential subject id must match the holder subject");
                LogVerificationFailure(result.Status);
                return result;
            }

            credentialSubject = JsonSerializer.Deserialize<Dictionary<string, object>>(csJson);
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
                "Credential has expired");
            LogVerificationFailure(result.Status);
            return result;
        }

        // T027: Resolve issuer DID from database with ENFORCED tenant isolation
        // SECURITY: Always filter by tenant ID to prevent cross-tenant access
        var issuerDidEntity = await _dbContext.Dids
            .Where(d => d.DidIdentifier == issuerDid && d.TenantId == issuerTenantId)
            .Select(d => new { d.PublicKeyEd25519, d.Status })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (issuerDidEntity == null)
        {
            var result = CreateFailedResult(
                VerificationStatus.IssuerNotFound,
                "Issuer DID not found");
            if (_logger != null)
            {
                _logIssuerNotFound(_logger, issuerDid, issuerTenantId, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // SECURITY: Check if issuer DID is deactivated
        if (issuerDidEntity.Status == "deactivated")
        {
            var result = CreateFailedResult(
                VerificationStatus.IssuerNotFound,
                "Issuer DID is deactivated");
            if (_logger != null)
            {
                _logDeactivatedIssuerAttempt(_logger, issuerDid, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // T028: Verify Ed25519 signature
        var isSignatureValid = Ed25519JwtSigner.VerifySignedJwt(
            credentialJwt,
            issuerDidEntity.PublicKeyEd25519);

        if (!isSignatureValid)
        {
            var result = CreateFailedResult(
                VerificationStatus.SignatureInvalid,
                "Signature verification failed");
            if (_logger != null)
            {
                _logSignatureVerificationFailed(_logger, issuerDid, null);
            }
            LogVerificationFailure(result.Status);
            return result;
        }

        // Canonical encodings keep equivalent signatures from bypassing the exact-token revocation lookup.
        if (!StrictJwtReader.IsCanonicalCompact(credentialJwt, MaxJwtSizeBytes))
        {
            var result = CreateFailedResult(VerificationStatus.MalformedJwt, "JWT must use canonical compact base64url encoding");
            LogVerificationFailure(result.Status);
            return result;
        }

        // T028a: Check credential revocation status
        // SECURITY: Check if credential has been revoked (with tenant isolation)
        var credential = await _dbContext.VerifiableCredentials
            .Where(vc => vc.CredentialJwt == credentialJwt && vc.TenantId == issuerTenantId && vc.Status == "revoked")
            .Select(vc => new { vc.Id })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (credential != null)
        {
            var result = CreateFailedResult(
                VerificationStatus.Revoked,
                "Credential has been revoked");
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

    private static bool HasLocalCredentialTypes(JsonElement vc)
    {
        if (!vc.TryGetProperty("type", out var types) || types.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var hasBaseType = false;
        var hasSpecificType = false;
        foreach (var type in types.EnumerateArray())
        {
            if (type.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var name = type.GetString();
            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            if (string.Equals(name, "VerifiableCredential", StringComparison.Ordinal))
            {
                hasBaseType = true;
            }
            else
            {
                hasSpecificType = true;
            }
        }

        return hasBaseType && hasSpecificType;
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
        string errorMessage)
    {
        return new CredentialVerificationResult
        {
            IsValid = false,
            Status = status,
            // A rejected credential never publishes parsed values as verified identity data.
            ValidationErrors = new[] { errorMessage }
        };
    }
}
