using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.SdJwt;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Service for creating and verifying W3C Verifiable Presentations with selective disclosure
/// Implements SD-JWT (Selective Disclosure for JWTs) per IETF draft-22
/// </summary>
public sealed class VerifiablePresentationService : IVerifiablePresentationService
{
    private const string RateLimitOperationType = "PRESENTATION_CREATE";

    private readonly HeroDbContext _dbContext;
    private readonly ISdJwtGenerator _sdJwtGenerator;
    private readonly ISdJwtVerifier _sdJwtVerifier;
    private readonly IRateLimiter _rateLimiter;
    private readonly IKeyEncryptionService _keyEncryptionService;
    private readonly ILogger<VerifiablePresentationService>? _logger;

    /// <summary>
    /// Initializes a new instance of the VerifiablePresentationService
    /// </summary>
    public VerifiablePresentationService(
        HeroDbContext dbContext,
        ISdJwtGenerator sdJwtGenerator,
        ISdJwtVerifier sdJwtVerifier,
        IRateLimiter rateLimiter,
        IKeyEncryptionService keyEncryptionService,
        ILogger<VerifiablePresentationService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(sdJwtGenerator);
        ArgumentNullException.ThrowIfNull(sdJwtVerifier);
        ArgumentNullException.ThrowIfNull(rateLimiter);
        ArgumentNullException.ThrowIfNull(keyEncryptionService);

        _dbContext = dbContext;
        _sdJwtGenerator = sdJwtGenerator;
        _sdJwtVerifier = sdJwtVerifier;
        _rateLimiter = rateLimiter;
        _keyEncryptionService = keyEncryptionService;
        _logger = logger;
    }

    /// <summary>
    /// Creates a Verifiable Presentation from a credential with selective disclosure
    /// </summary>
    public async Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext,
        string credentialJwt,
        string[]? claimsToDisclose,
        Guid holderDidId,
        string? audience = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (string.IsNullOrWhiteSpace(credentialJwt))
        {
            throw new ArgumentException("Credential JWT cannot be null or empty", nameof(credentialJwt));
        }

        var tenantId = tenantContext.GetCurrentTenantId();

        // Rate limiting
        var isAllowed = await _rateLimiter.IsAllowedAsync(
            tenantId,
            RateLimitOperationType,
            cancellationToken).ConfigureAwait(false);

        if (!isAllowed)
        {
            throw new InvalidOperationException("Rate limit exceeded for presentation creation");
        }

        // Resolve holder DID with tenant isolation
        var holderDid = await _dbContext.Dids
            .Where(d => d.Id == holderDidId && d.TenantId == tenantId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (holderDid == null)
        {
            throw new ArgumentException("Holder DID not found or does not belong to tenant", nameof(holderDidId));
        }

        // Parse credential JWT to extract claims
        var payload = Ed25519JwtHelper.ExtractPayload(credentialJwt);
        var payloadDoc = JsonDocument.Parse(payload);

        // Extract credential subject claims
        Dictionary<string, object> allClaims = new();
        if (payloadDoc.RootElement.TryGetProperty("vc", out var vc) &&
            vc.TryGetProperty("credentialSubject", out var credentialSubject))
        {
            var claimsJson = credentialSubject.GetRawText();
            allClaims = JsonSerializer.Deserialize<Dictionary<string, object>>(claimsJson) ?? new();
        }

        // Determine which claims to disclose (null = all claims)
        var selectedClaimNames = claimsToDisclose ?? allClaims.Keys.ToArray();

        // Filter claims based on selection
        var claimsToInclude = allClaims
            .Where(kv => selectedClaimNames.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value);

        // SECURITY: Decrypt private key and ensure it's cleared from memory after use
        byte[]? decryptedPrivateKey = null;
        try
        {
            // Decrypt the holder's private key
            decryptedPrivateKey = _keyEncryptionService.Decrypt(holderDid.PrivateKeyEd25519Encrypted);

            // Create VP-JWT with selective disclosure using SD-JWT
            // MOCK: For MVP, this uses MockSdJwtGenerator which creates standard JWT
            // Real HeroSD-JWT library will create proper SD-JWT with hash-based disclosures
            var sdJwtResult = _sdJwtGenerator.GenerateSdJwt(
                claims: claimsToInclude,
                selectiveDisclosureClaims: selectedClaimNames,
                signingKey: decryptedPrivateKey,
                issuerDid: holderDid.DidIdentifier,
                holderDid: holderDid.DidIdentifier);

            // Record operation for rate limiting
            await _rateLimiter.RecordOperationAsync(
                tenantId,
                RateLimitOperationType,
                cancellationToken).ConfigureAwait(false);

            return new PresentationResult
            {
                PresentationJwt = sdJwtResult.CompactSdJwt,
                SelectedDisclosures = sdJwtResult.DisclosureTokens,
                DisclosedClaimNames = selectedClaimNames
            };
        }
        finally
        {
            // SECURITY: Clear decrypted private key from memory (even if exception occurred)
            if (decryptedPrivateKey != null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(decryptedPrivateKey);
            }
        }
    }

    /// <summary>
    /// Verifies a Verifiable Presentation and validates selective disclosures
    /// </summary>
    public async Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext tenantContext,
        string presentationJwt,
        string[] disclosureTokens,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (string.IsNullOrWhiteSpace(presentationJwt))
        {
            throw new ArgumentException("Presentation JWT cannot be null or empty", nameof(presentationJwt));
        }

        ArgumentNullException.ThrowIfNull(disclosureTokens);

        var tenantId = tenantContext.GetCurrentTenantId();

        // Extract issuer DID from presentation to look up public key
        var jwtPart = presentationJwt.Split('~')[0];
        var payload = Ed25519JwtHelper.ExtractPayload(jwtPart);
        var payloadDoc = JsonDocument.Parse(payload);

        string? issuerDidIdentifier = null;
        if (payloadDoc.RootElement.TryGetProperty("iss", out var iss))
        {
            issuerDidIdentifier = iss.GetString();
        }

        if (string.IsNullOrEmpty(issuerDidIdentifier))
        {
            return new PresentationVerificationResult
            {
                IsValid = false,
                Status = PresentationVerificationStatus.MalformedPresentation,
                ValidationErrors = new[] { "Issuer DID not found in presentation" }
            };
        }

        // Resolve issuer DID for public key (with tenant isolation)
        var issuerDid = await _dbContext.Dids
            .Where(d => d.DidIdentifier == issuerDidIdentifier && d.TenantId == tenantId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (issuerDid == null)
        {
            return new PresentationVerificationResult
            {
                IsValid = false,
                Status = PresentationVerificationStatus.IssuerNotFound,
                ValidationErrors = new[] { $"Issuer DID not found: {issuerDidIdentifier}" }
            };
        }

        // Verify SD-JWT using mock verifier
        // MOCK: For MVP, this uses MockSdJwtVerifier which verifies standard JWT
        // Real HeroSD-JWT library will validate disclosure tokens against hash digests
        var sdJwtResult = _sdJwtVerifier.VerifySdJwt(
            presentationJwt,
            disclosureTokens,
            issuerDid.PublicKeyEd25519);

        if (!sdJwtResult.IsValid)
        {
            var status = sdJwtResult.Status switch
            {
                SdJwtVerificationStatus.SignatureInvalid => PresentationVerificationStatus.CredentialSignatureInvalid,
                SdJwtVerificationStatus.DisclosureMismatch => PresentationVerificationStatus.DisclosureMismatch,
                SdJwtVerificationStatus.MalformedSdJwt => PresentationVerificationStatus.MalformedPresentation,
                SdJwtVerificationStatus.IssuerNotFound => PresentationVerificationStatus.IssuerNotFound,
                _ => PresentationVerificationStatus.MalformedPresentation
            };

            return new PresentationVerificationResult
            {
                IsValid = false,
                Status = status,
                ValidationErrors = sdJwtResult.ValidationErrors,
                DisclosedClaims = sdJwtResult.DisclosedClaims,
                HolderDid = sdJwtResult.HolderDid,
                IssuerDids = sdJwtResult.IssuerDid != null ? new[] { sdJwtResult.IssuerDid } : null
            };
        }

        return new PresentationVerificationResult
        {
            IsValid = true,
            Status = PresentationVerificationStatus.Valid,
            ValidationErrors = Array.Empty<string>(),
            DisclosedClaims = sdJwtResult.DisclosedClaims,
            HolderDid = sdJwtResult.HolderDid,
            IssuerDids = sdJwtResult.IssuerDid != null ? new[] { sdJwtResult.IssuerDid } : null
        };
    }
}
