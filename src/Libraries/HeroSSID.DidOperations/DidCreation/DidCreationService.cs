using System.Security.Cryptography;
using HeroSSID.Core.DidMethod;
using HeroSSID.Core.KeyEncryption;
using HeroSSID.Core.RateLimiting;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.DidOperations.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.DidCreation;

/// <summary>
/// Service for creating W3C-compliant DIDs with Ed25519 cryptography
/// Generates did:key identifiers using Ed25519 signatures via NSec library (libsodium-based)
/// Implements W3C DID Core 1.0 specification with secure key storage and memory handling
/// </summary>
public sealed class DidCreationService : IDidCreationService
{
    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _keyEncryptionService;
    private readonly ITenantContext _tenantContext;
    private readonly DidMethodResolver _didMethodResolver;
    private readonly IRateLimiter? _rateLimiter; // Optional for backward compatibility
    private readonly ILogger<DidCreationService> _logger;

    // LoggerMessage delegates
    private static readonly Action<ILogger, Exception?> s_logStartingDidCreation =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1, nameof(CreateDidAsync)),
            "Starting DID creation process");

    private static readonly Action<ILogger, int, int, Exception?> s_logGeneratingKeyPair =
        LoggerMessage.Define<int, int>(
            LogLevel.Debug,
            new EventId(2, nameof(CreateDidAsync)),
            "Generating Ed25519 key pair (attempt {Attempt}/{MaxRetries})");

    private static readonly Action<ILogger, Exception?> s_logGeneratingDidIdentifier =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(3, nameof(CreateDidAsync)),
            "Generating DID identifier");

    private static readonly Action<ILogger, string, int, int, Exception?> s_logDidCollision =
        LoggerMessage.Define<string, int, int>(
            LogLevel.Warning,
            new EventId(4, nameof(CreateDidAsync)),
            "DID identifier collision detected: {DidIdentifier}. Retrying with new keys (attempt {Attempt}/{MaxRetries})");

    private static readonly Action<ILogger, Exception?> s_logEncryptingPrivateKey =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(5, nameof(CreateDidAsync)),
            "Encrypting private key");

    private static readonly Action<ILogger, Exception?> s_logCreatingDidDocument =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(6, nameof(CreateDidAsync)),
            "Creating W3C DID Document");

    private static readonly Action<ILogger, int, int, Exception?> s_logRaceCondition =
        LoggerMessage.Define<int, int>(
            LogLevel.Warning,
            new EventId(7, nameof(CreateDidAsync)),
            "Race condition detected during DID save. Retrying with new keys (attempt {Attempt}/{MaxRetries})");

    private static readonly Action<ILogger, string, int, Exception?> s_logDidCreatedSuccessfully =
        LoggerMessage.Define<string, int>(
            LogLevel.Information,
            new EventId(8, nameof(CreateDidAsync)),
            "DID created successfully: {DidIdentifier} (attempt {Attempt})");

    private static readonly Action<ILogger, int, Exception?> s_logDidCreationFailed =
        LoggerMessage.Define<int>(
            LogLevel.Error,
            new EventId(9, nameof(CreateDidAsync)),
            "Failed to create DID after {Attempt} attempts");

    private static readonly Action<ILogger, Guid, Exception?> s_logKeyReuseDetected =
        LoggerMessage.Define<Guid>(
            LogLevel.Warning,
            new EventId(10, nameof(CreateDidAsync)),
            "Key reuse detected - same public key fingerprint already exists for tenant {TenantId}. Retrying with new key.");

    public DidCreationService(
        HeroDbContext dbContext,
        IKeyEncryptionService keyEncryptionService,
        ITenantContext tenantContext,
        DidMethodResolver didMethodResolver,
        ILogger<DidCreationService> logger,
        IRateLimiter? rateLimiter = null) // Optional for backward compatibility
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _keyEncryptionService = keyEncryptionService ?? throw new ArgumentNullException(nameof(keyEncryptionService));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
        _didMethodResolver = didMethodResolver ?? throw new ArgumentNullException(nameof(didMethodResolver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _rateLimiter = rateLimiter; // Optional - will skip rate limiting if null
    }

    /// <inheritdoc />
    public async Task<DidCreationResult> CreateDidAsync(CancellationToken cancellationToken = default)
    {
        // SECURITY: Check rate limit to prevent resource exhaustion attacks
        if (_rateLimiter != null)
        {
            Guid tenantId = _tenantContext.GetCurrentTenantId();
            bool isAllowed = await _rateLimiter.IsAllowedAsync(tenantId, "DID_CREATE", cancellationToken).ConfigureAwait(false);

            if (!isAllowed)
            {
                throw new InvalidOperationException("Rate limit exceeded for DID creation. Please try again later.");
            }

            // Record this operation for rate limiting
            await _rateLimiter.RecordOperationAsync(tenantId, "DID_CREATE", cancellationToken).ConfigureAwait(false);
        }

        s_logStartingDidCreation(_logger, null);

        const int maxRetries = 3;
        int attempt = 0;

        while (attempt < maxRetries)
        {
            attempt++;

            // Initialize key variables outside try to ensure they're in scope for finally
            byte[]? publicKey = null;
            byte[]? privateKey = null;
            byte[]? encryptedPrivateKey = null;

            try
            {
                // Step 1: Generate Ed25519 key pair
                s_logGeneratingKeyPair(_logger, attempt, maxRetries, null);
                (publicKey, privateKey) = GenerateEd25519KeyPair();

                // Step 2: Generate DID identifier from public key using did:key method
                s_logGeneratingDidIdentifier(_logger, null);
                IDidMethod didMethod = _didMethodResolver.GetMethod("key");
                string didIdentifier = didMethod.GenerateDidIdentifier(publicKey);

                // SECURITY: Get tenant context for collision check
                Guid tenantId = _tenantContext.GetCurrentTenantId();

                // Step 2a: Check for DID identifier collision within tenant scope
                bool didExists = await _dbContext.Dids
                    .AnyAsync(d => d.DidIdentifier == didIdentifier && d.TenantId == tenantId, cancellationToken).ConfigureAwait(false);

                if (didExists)
                {
                    s_logDidCollision(_logger, didIdentifier, attempt, maxRetries, null);

                    // Keys will be cleared in finally block
                    if (attempt < maxRetries)
                    {
                        continue; // Retry with new keys
                    }
                    else
                    {
                        throw new InvalidOperationException($"Failed to generate unique DID identifier after {maxRetries} attempts");
                    }
                }

                // Step 3: Encrypt private key for secure storage
                s_logEncryptingPrivateKey(_logger, null);
                encryptedPrivateKey = _keyEncryptionService.Encrypt(privateKey);

                // Validate encryption output is non-empty and different from input
                if (encryptedPrivateKey == null || encryptedPrivateKey.Length == 0)
                {
                    throw new InvalidOperationException("Encryption service returned empty result");
                }
                if (encryptedPrivateKey.SequenceEqual(privateKey))
                {
                    throw new InvalidOperationException("Encryption service did not encrypt the private key");
                }

                // Securely clear private key from memory immediately after successful encryption
                SecureZeroMemory(privateKey);
                privateKey = null; // Mark as cleared

                // Step 4: Create W3C DID Document using did:key method
                s_logCreatingDidDocument(_logger, null);
                string didDocumentJson = didMethod.CreateDidDocument(didIdentifier, publicKey);

                // Step 5: Create entity and save to database
                DateTimeOffset createdAt = DateTimeOffset.UtcNow;

                // Create copies of arrays for entity storage (arrays are reference types)
                // This prevents the subsequent SecureZeroMemory calls from zeroing the entity's data
                byte[] publicKeyCopy = new byte[publicKey.Length];
                Array.Copy(publicKey, publicKeyCopy, publicKey.Length);

                // SECURITY: Calculate key fingerprint for key reuse detection BEFORE clearing original
                byte[] keyFingerprint = CalculateKeyFingerprint(publicKey);

                // SECURITY: Check for key reuse within tenant scope
                // TIMING ATTACK: SequenceEqual in EF Core LINQ translates to SQL comparison (database-side),
                // so timing attacks are not a concern here as the comparison happens in PostgreSQL, not in .NET memory
                Guid currentTenantId = _tenantContext.GetCurrentTenantId();
                bool keyReused = await _dbContext.Dids
                    .AnyAsync(d => d.KeyFingerprint.SequenceEqual(keyFingerprint) && d.TenantId == currentTenantId, cancellationToken)
                    .ConfigureAwait(false);

                if (keyReused)
                {
                    s_logKeyReuseDetected(_logger, currentTenantId, null);
                    SecureZeroMemory(keyFingerprint);

                    // Keys will be cleared in finally block
                    if (attempt < maxRetries)
                    {
                        continue; // Retry with new keys
                    }
                    else
                    {
                        throw new InvalidOperationException($"Failed to generate unique key pair after {maxRetries} attempts - key reuse detected");
                    }
                }

                // SECURITY: Clear original public key immediately after copy
                SecureZeroMemory(publicKey);
                publicKey = null;

                byte[] encryptedPrivateKeyCopy = new byte[encryptedPrivateKey.Length];
                Array.Copy(encryptedPrivateKey, encryptedPrivateKeyCopy, encryptedPrivateKey.Length);

                // SECURITY: Clear original encrypted private key immediately after copy
                SecureZeroMemory(encryptedPrivateKey);
                encryptedPrivateKey = null;

                DidEntity didEntity = new DidEntity
                {
                    Id = Guid.NewGuid(),
                    TenantId = _tenantContext.GetCurrentTenantId(),
                    DidIdentifier = didIdentifier,
                    PublicKeyEd25519 = publicKeyCopy,
                    KeyFingerprint = keyFingerprint,
                    PrivateKeyEd25519Encrypted = encryptedPrivateKeyCopy,
                    DidDocumentJson = didDocumentJson,
                    Status = "active",
                    CreatedAt = createdAt
                };

                _dbContext.Dids.Add(didEntity);

                try
                {
                    await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

                    // SECURITY: Immediately clone the arrays for return result BEFORE clearing entity
                    // This minimizes the time window where sensitive data exists in entity memory
                    byte[] publicKeyForResult = (byte[])didEntity.PublicKeyEd25519.Clone();
                    byte[] encryptedPrivateKeyForResult = (byte[])didEntity.PrivateKeyEd25519Encrypted.Clone();

                    // SECURITY: Clear sensitive data from entity IMMEDIATELY after cloning for result
                    // This minimizes sensitive data lifetime in memory
                    SecureZeroMemory(didEntity.PublicKeyEd25519);
                    SecureZeroMemory(didEntity.KeyFingerprint);
                    SecureZeroMemory(didEntity.PrivateKeyEd25519Encrypted);
                    _dbContext.Entry(didEntity).State = EntityState.Detached;

                    s_logDidCreatedSuccessfully(_logger, didIdentifier, attempt, null);

                    // Step 6: Return result with cloned arrays
                    return new DidCreationResult
                    {
                        Id = didEntity.Id,
                        TenantId = didEntity.TenantId,
                        DidIdentifier = didIdentifier,
                        PublicKey = publicKeyForResult,
                        EncryptedPrivateKey = encryptedPrivateKeyForResult,
                        DidDocumentJson = didDocumentJson,
                        Status = "active",
                        CreatedAt = createdAt
                    };
                }
                catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("duplicate", StringComparison.OrdinalIgnoreCase) == true)
                {
                    // Handle race condition where another thread created the same DID between our check and save
                    s_logRaceCondition(_logger, attempt, maxRetries, ex);

                    // SECURITY: Clear sensitive data from failed entity before retrying
                    SecureZeroMemory(didEntity.PublicKeyEd25519);
                    SecureZeroMemory(didEntity.KeyFingerprint);
                    SecureZeroMemory(didEntity.PrivateKeyEd25519Encrypted);

                    // Remove the failed entity from tracking
                    _dbContext.Entry(didEntity).State = EntityState.Detached;

                    // Keys will be cleared in finally block
                    if (attempt < maxRetries)
                    {
                        continue; // Retry with new keys
                    }
                    else
                    {
                        throw new InvalidOperationException($"Failed to save DID after {maxRetries} attempts due to collisions", ex);
                    }
                }
            }
            catch (Exception ex) when (attempt >= maxRetries ||
                                        (ex is not InvalidOperationException && ex is not DbUpdateException))
            {
                s_logDidCreationFailed(_logger, attempt, ex);
                throw;
            }
            finally
            {
                // Always clear sensitive data from memory, regardless of success or failure
                // This ensures keys are zeroed even if exceptions occur
                if (publicKey != null)
                {
                    SecureZeroMemory(publicKey);
                }
                if (privateKey != null)
                {
                    SecureZeroMemory(privateKey);
                }
                if (encryptedPrivateKey != null)
                {
                    SecureZeroMemory(encryptedPrivateKey);
                }
            }
        }

        // This should never be reached, but added for completeness
        throw new InvalidOperationException("Failed to create DID: unexpected end of retry loop");
    }

    /// <summary>
    /// Generates an Ed25519 key pair for signing using NSec library (libsodium-based)
    /// </summary>
    /// <returns>Tuple of (publicKey, privateKey)</returns>
    /// <remarks>
    /// Ed25519 produces 32-byte public keys and 32-byte private seeds.
    /// This implementation uses NSec.Cryptography which is a modern .NET wrapper
    /// around libsodium, providing production-ready Ed25519 cryptographic operations.
    /// </remarks>
    private static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
    {
        // SECURITY: Validate system has sufficient entropy before generating keys
        // This protects against weak key generation on fresh VMs or containers with poor entropy
        ValidateSystemEntropy();

        // Use NSec's Ed25519 signature algorithm
        SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

        // Configure key creation to allow export (required for database storage)
        // NSec defaults to non-exportable keys for security, but we need to persist them
        KeyCreationParameters keyParams = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        // Generate a new key using NSec's Key class
        // This generates a cryptographically secure Ed25519 keypair
        using Key key = Key.Create(algorithm, keyParams);

        // Export public key (32 bytes)
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        // Export private key seed (32 bytes)
        // Note: Ed25519 private key is actually a 32-byte seed from which the keypair is derived
        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);

        // SECURITY: Validate generated keys are not all zeros (indicates failed generation)
        if (publicKey.All(b => b == 0) || privateKey.All(b => b == 0))
        {
            throw new CryptographicException("Key generation produced invalid all-zero keys - insufficient entropy or generation failure");
        }

        // SECURITY: Validate key pair by performing test signature/verification
        // This ensures the keys are mathematically valid and work correctly
        ValidateKeyPair(algorithm, publicKey, privateKey);

        return (publicKey, privateKey);
    }

    /// <summary>
    /// Validates that the system has sufficient entropy for secure key generation.
    /// SECURITY: This is a critical defense against weak key generation on systems with poor entropy sources.
    /// Uses larger sample size and statistical tests for robust validation.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown if entropy validation fails</exception>
    private static void ValidateSystemEntropy()
    {
        // Use larger sample for more reliable entropy testing
        const int sampleSize = 256;
        byte[] entropyTest = new byte[sampleSize];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(entropyTest);
        }

        // Check for obvious patterns indicating poor entropy:
        // 1. All bytes are the same (complete failure)
        if (entropyTest.All(b => b == entropyTest[0]))
        {
            throw new CryptographicException("CRITICAL: System RNG failed entropy test - all bytes identical. Key generation aborted.");
        }

        // 2. All bytes are zero (common failure mode)
        if (entropyTest.All(b => b == 0))
        {
            throw new CryptographicException("CRITICAL: System RNG returned all zeros - insufficient entropy. Key generation aborted.");
        }

        // 3. All bytes are 0xFF (another common failure mode)
        if (entropyTest.All(b => b == 0xFF))
        {
            throw new CryptographicException("CRITICAL: System RNG returned all 0xFF - insufficient entropy. Key generation aborted.");
        }

        // 4. Check for sufficient unique values (require at least 50% unique bytes)
        int uniqueBytes = entropyTest.Distinct().Count();
        int minUniqueBytes = sampleSize / 2; // 128 of 256
        if (uniqueBytes < minUniqueBytes)
        {
            throw new CryptographicException($"CRITICAL: System RNG has insufficient entropy - only {uniqueBytes} unique values in {sampleSize} bytes (minimum: {minUniqueBytes}). Key generation aborted.");
        }

        // 5. Chi-square test for uniform distribution
        // Divide byte range (0-255) into 16 buckets of 16 values each
        int[] buckets = new int[16];
        foreach (byte b in entropyTest)
        {
            buckets[b / 16]++;
        }

        // Calculate chi-square statistic
        double expectedCount = sampleSize / 16.0; // 256 / 16 = 16 samples per bucket expected
        double chiSquare = buckets.Sum(count => Math.Pow(count - expectedCount, 2) / expectedCount);

        // Chi-square critical value for 15 degrees of freedom at 99% confidence is ~30.58
        // If chi-square exceeds this, the distribution is non-uniform (potential entropy issue)
        const double chiSquareCriticalValue = 30.58;
        if (chiSquare > chiSquareCriticalValue)
        {
            throw new CryptographicException($"CRITICAL: System RNG failed distribution test (chi-square: {chiSquare:F2} > {chiSquareCriticalValue}). Key generation aborted.");
        }
    }

    /// <summary>
    /// Validates a generated key pair by performing a test signature and verification.
    /// SECURITY: This ensures the keys are mathematically valid and work correctly before storage.
    /// </summary>
    /// <param name="algorithm">The signature algorithm to use (Ed25519)</param>
    /// <param name="publicKey">Public key bytes to validate</param>
    /// <param name="privateKey">Private key bytes to validate</param>
    /// <exception cref="CryptographicException">Thrown if key validation fails</exception>
    private static void ValidateKeyPair(SignatureAlgorithm algorithm, byte[] publicKey, byte[] privateKey)
    {
        byte[]? testSignature = null;

        try
        {
            // Create test message for signing
            byte[] testMessage = System.Text.Encoding.UTF8.GetBytes("HeroSSID key validation test");

            // Import private key and create test signature
            using Key testKey = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
            testSignature = algorithm.Sign(testKey, testMessage);

            // Verify signature fails with null or empty signature
            if (testSignature == null || testSignature.Length == 0)
            {
                throw new CryptographicException("Generated key pair validation failed: signature creation produced empty result");
            }

            // Import public key and verify the signature
            PublicKey testPublicKey = PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);
            bool isValid = algorithm.Verify(testPublicKey, testMessage, testSignature);

            if (!isValid)
            {
                throw new CryptographicException("Generated key pair validation failed: signature verification failed");
            }
        }
        catch (CryptographicException)
        {
            // Re-throw cryptographic exceptions as-is
            throw;
        }
        catch (Exception ex)
        {
            // Wrap other exceptions with context
            throw new CryptographicException("Generated key pair validation failed with unexpected error", ex);
        }
        finally
        {
            // SECURITY: Clear test signature from memory
            if (testSignature != null)
            {
                SecureZeroMemory(testSignature);
            }
        }
    }

    /// <summary>
    /// Calculates a SHA-256 fingerprint of a public key for key reuse detection.
    /// </summary>
    /// <param name="publicKey">The public key bytes to fingerprint</param>
    /// <returns>32-byte SHA-256 hash of the public key</returns>
    /// <remarks>
    /// SECURITY: This fingerprint is used to detect if the same cryptographic key is being
    /// reused across multiple DIDs, which is a security anti-pattern that reduces key isolation.
    /// </remarks>
    private static byte[] CalculateKeyFingerprint(byte[] publicKey)
    {
        return SHA256.HashData(publicKey);
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
