using System.Security.Cryptography;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.DidSigning;

/// <summary>
/// Implementation of signing and verification operations using Ed25519.
/// Uses NSec.Cryptography (libsodium wrapper) for cryptographic operations.
/// </summary>
#pragma warning disable CA1848 // Use LoggerMessage delegates - not needed for MVP
public sealed class DidSigningService(
    HeroDbContext dbContext,
    IKeyEncryptionService keyEncryptionService,
    ITenantContext tenantContext,
    ILogger<DidSigningService> logger,
    IRateLimiter? rateLimiter = null) : IDidSigningService
{
    private readonly HeroDbContext _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
    private readonly IKeyEncryptionService _keyEncryptionService = keyEncryptionService ?? throw new ArgumentNullException(nameof(keyEncryptionService));
    private readonly ITenantContext _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
    private readonly IRateLimiter? _rateLimiter = rateLimiter; // Optional for backward compatibility
    private readonly ILogger<DidSigningService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    public async Task<byte[]> SignAsync(string didIdentifier, byte[] message, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);
        ArgumentNullException.ThrowIfNull(message);

        // SECURITY: Check rate limit to prevent resource exhaustion attacks
        if (_rateLimiter != null)
        {
            Guid rateLimitTenantId = _tenantContext.GetCurrentTenantId();
            bool isAllowed = await _rateLimiter.IsAllowedAsync(rateLimitTenantId, "DID_SIGN", cancellationToken).ConfigureAwait(false);

            if (!isAllowed)
            {
                throw new InvalidOperationException("Rate limit exceeded for DID signing. Please try again later.");
            }

            // Record this operation for rate limiting
            await _rateLimiter.RecordOperationAsync(rateLimitTenantId, "DID_SIGN", cancellationToken).ConfigureAwait(false);
        }

        // SECURITY: Get current tenant context
        Guid tenantId = _tenantContext.GetCurrentTenantId();

        // Retrieve DID from database with tenant isolation
        var didEntity = await _dbContext.Dids
            .AsNoTracking()
            .FirstOrDefaultAsync(d => d.DidIdentifier == didIdentifier && d.TenantId == tenantId, cancellationToken)
            .ConfigureAwait(false);

        if (didEntity == null)
        {
            throw new InvalidOperationException($"DID not found: {didIdentifier}");
        }

        if (didEntity.Status != "active")
        {
            throw new InvalidOperationException($"DID is not active: {didIdentifier} (status: {didEntity.Status})");
        }

        byte[]? decryptedPrivateKey = null;

        try
        {
            // Decrypt private key
            decryptedPrivateKey = _keyEncryptionService.Decrypt(didEntity.PrivateKeyEd25519Encrypted);

            // Sign message using Ed25519
            byte[] signature = SignMessage(decryptedPrivateKey, message);

            _logger.LogInformation("Signed message with DID {DidIdentifier}, signature length: {SignatureLength} bytes",
                didIdentifier, signature.Length);

            return signature;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Cryptographic error while signing with DID {DidIdentifier}", didIdentifier);
            throw;
        }
        finally
        {
            // SECURITY: Clear decrypted private key from memory
            if (decryptedPrivateKey != null)
            {
                SecureZeroMemory(decryptedPrivateKey);
            }
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(string didIdentifier, byte[] message, byte[] signature, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);

        // SECURITY: Get current tenant context
        Guid tenantId = _tenantContext.GetCurrentTenantId();

        // Retrieve DID from database with tenant isolation
        var didEntity = await _dbContext.Dids
            .AsNoTracking()
            .FirstOrDefaultAsync(d => d.DidIdentifier == didIdentifier && d.TenantId == tenantId, cancellationToken)
            .ConfigureAwait(false);

        if (didEntity == null)
        {
            throw new InvalidOperationException($"DID not found: {didIdentifier}");
        }

        // Verify signature using public key
        bool isValid = VerifyWithPublicKey(didEntity.PublicKeyEd25519, message, signature);

        _logger.LogInformation("Verified signature for DID {DidIdentifier}: {IsValid}", didIdentifier, isValid);

        return isValid;
    }

    /// <inheritdoc />
    public bool VerifyWithPublicKey(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);

        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(publicKey));
        }

        if (signature.Length != 64)
        {
            throw new ArgumentException("Ed25519 signature must be 64 bytes", nameof(signature));
        }

        try
        {
            return VerifySignature(publicKey, message, signature);
        }
#pragma warning disable CA1031 // Do not catch general exception types - verification should not throw
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogWarning(ex, "Signature verification failed with exception");
            return false;
        }
    }

    /// <summary>
    /// Signs a message using Ed25519 private key.
    /// </summary>
    /// <param name="privateKey">32-byte Ed25519 private key seed</param>
    /// <param name="message">Message bytes to sign</param>
    /// <returns>64-byte Ed25519 signature</returns>
    private static byte[] SignMessage(byte[] privateKey, byte[] message)
    {
        SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

        // Import private key
        using Key key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);

        // Sign message
        byte[] signature = algorithm.Sign(key, message);

        if (signature.Length != 64)
        {
            throw new CryptographicException($"Ed25519 signature should be 64 bytes, got {signature.Length}");
        }

        return signature;
    }

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key</param>
    /// <param name="message">Original message bytes</param>
    /// <param name="signature">64-byte Ed25519 signature</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    private static bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
    {
        SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

        // Import public key
        PublicKey pubKey = PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);

        // Verify signature
        return algorithm.Verify(pubKey, message, signature);
    }

    /// <summary>
    /// Securely zeros sensitive data from memory to prevent recovery from memory dumps.
    /// Uses unsafe code to pin the array and ensure the compiler doesn't optimize away the zeroing.
    /// </summary>
    /// <param name="buffer">The sensitive buffer to zero</param>
    private static void SecureZeroMemory(byte[] buffer)
    {
        if (buffer == null || buffer.Length == 0)
        {
            return;
        }

        // Pin the array in memory to prevent garbage collector from moving it
        System.Runtime.InteropServices.GCHandle handle = System.Runtime.InteropServices.GCHandle.Alloc(buffer, System.Runtime.InteropServices.GCHandleType.Pinned);
        try
        {
            // Use unsafe code to ensure zeroing isn't optimized away by the compiler
            unsafe
            {
                byte* ptr = (byte*)handle.AddrOfPinnedObject();
                for (int i = 0; i < buffer.Length; i++)
                {
                    ptr[i] = 0;
                }
            }
        }
        finally
        {
            handle.Free();
        }
    }
}
