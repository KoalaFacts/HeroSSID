using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Models;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.Helpers;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Services;

/// <summary>
/// Service for creating W3C-compliant DIDs with Ed25519 cryptography
/// Generates did:key identifiers using Ed25519 signatures via NSec library (libsodium-based)
/// Implements W3C DID Core 1.0 specification with secure key storage and memory handling
/// </summary>
public sealed class DidCreationService : IDidCreationService
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _keyEncryptionService;
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

    public DidCreationService(
        HeroDbContext dbContext,
        IKeyEncryptionService keyEncryptionService,
        ILogger<DidCreationService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _keyEncryptionService = keyEncryptionService ?? throw new ArgumentNullException(nameof(keyEncryptionService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<DidCreationResult> CreateDidAsync(CancellationToken cancellationToken = default)
    {
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

                // Step 2: Generate DID identifier from public key
                s_logGeneratingDidIdentifier(_logger, null);
                string didIdentifier = GenerateDidIdentifier(publicKey);

                // Step 2a: Check for DID identifier collision
                bool didExists = await _dbContext.Dids
                    .AnyAsync(d => d.DidIdentifier == didIdentifier, cancellationToken).ConfigureAwait(false);

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

                // Step 4: Create W3C DID Document
                s_logCreatingDidDocument(_logger, null);
                string didDocumentJson = CreateDidDocument(didIdentifier, publicKey);

                // Step 5: Create entity and save to database
                DateTimeOffset createdAt = DateTimeOffset.UtcNow;

                // Create copies of arrays for entity storage (arrays are reference types)
                // This prevents the subsequent SecureZeroMemory calls from zeroing the entity's data
                byte[] publicKeyCopy = new byte[publicKey.Length];
                Array.Copy(publicKey, publicKeyCopy, publicKey.Length);

                byte[] encryptedPrivateKeyCopy = new byte[encryptedPrivateKey.Length];
                Array.Copy(encryptedPrivateKey, encryptedPrivateKeyCopy, encryptedPrivateKey.Length);

                DidEntity didEntity = new DidEntity
                {
                    Id = Guid.NewGuid(),
                    TenantId = HeroDbContext.DefaultTenantId,
                    DidIdentifier = didIdentifier,
                    PublicKeyEd25519 = publicKeyCopy,
                    PrivateKeyEd25519Encrypted = encryptedPrivateKeyCopy,
                    DidDocumentJson = didDocumentJson,
                    Status = "active",
                    CreatedAt = createdAt
                };

                _dbContext.Dids.Add(didEntity);

                try
                {
                    await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("duplicate", StringComparison.OrdinalIgnoreCase) == true)
                {
                    // Handle race condition where another thread created the same DID between our check and save
                    s_logRaceCondition(_logger, attempt, maxRetries, ex);

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

                s_logDidCreatedSuccessfully(_logger, didIdentifier, attempt, null);

                // Step 6: Return result
                // Clone arrays to prevent external code from modifying stored data
                var result = new DidCreationResult
                {
                    Id = didEntity.Id,
                    TenantId = didEntity.TenantId,
                    DidIdentifier = didEntity.DidIdentifier,
                    PublicKey = (byte[])didEntity.PublicKeyEd25519.Clone(),
                    EncryptedPrivateKey = (byte[])didEntity.PrivateKeyEd25519Encrypted.Clone(),
                    DidDocumentJson = didEntity.DidDocumentJson,
                    Status = didEntity.Status,
                    CreatedAt = didEntity.CreatedAt
                };

                // SECURITY: Clear sensitive data from entity and detach from tracking
                // After SaveChanges, we don't need the entity tracked anymore
                // Clear arrays before detaching to minimize sensitive data in memory
                SecureZeroMemory(didEntity.PublicKeyEd25519);
                SecureZeroMemory(didEntity.PrivateKeyEd25519Encrypted);
                _dbContext.Entry(didEntity).State = EntityState.Detached;

                return result;
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

        return (publicKey, privateKey);
    }

    /// <summary>
    /// Validates that the system has sufficient entropy for secure key generation.
    /// SECURITY: This is a critical defense against weak key generation on systems with poor entropy sources.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown if entropy validation fails</exception>
    private static void ValidateSystemEntropy()
    {
        // Generate test entropy from system RNG
        byte[] entropyTest = new byte[32];
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

        // 4. Check for minimal variance (at least 8 unique byte values expected in 32 bytes)
        int uniqueBytes = entropyTest.Distinct().Count();
        if (uniqueBytes < 8)
        {
            throw new CryptographicException($"CRITICAL: System RNG has insufficient entropy - only {uniqueBytes} unique values in 32 bytes. Key generation aborted.");
        }
    }

    /// <summary>
    /// Generates a DID identifier from a public key
    /// Format: did:key:z{multibase-multicodec-publicKey}
    /// Implements W3C did:key spec with proper multibase/multicodec encoding
    /// </summary>
    /// <param name="publicKey">Ed25519 public key (32 bytes)</param>
    /// <returns>DID identifier</returns>
    private static string GenerateDidIdentifier(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Public key must be 32 bytes for Ed25519", nameof(publicKey));
        }

        // 1. Add multicodec prefix (0xed01 for Ed25519-pub)
        byte[] multicodecKey = MulticodecHelper.AddEd25519Prefix(publicKey);

        // 2. Encode with Base58 Bitcoin alphabet
        string multibaseKey = SimpleBase.Base58.Bitcoin.Encode(multicodecKey);

        // 3. Add 'z' prefix for Base58 multibase encoding
        return $"did:key:z{multibaseKey}";
    }

    /// <summary>
    /// Extracts the public key from a DID identifier
    /// Reverses the multibase/multicodec encoding
    /// </summary>
    /// <param name="did">DID identifier (e.g., did:key:z...)</param>
    /// <returns>Ed25519 public key (32 bytes)</returns>
    private static byte[] ExtractPublicKeyFromDid(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);

        if (!did.StartsWith("did:key:z", StringComparison.Ordinal))
        {
            throw new ArgumentException("DID must start with 'did:key:z'", nameof(did));
        }

        // Extract multibase encoded portion
        string multibaseKey = did.Replace("did:key:z", "", StringComparison.Ordinal);

        // Decode Base58
        byte[] multicodecKey = SimpleBase.Base58.Bitcoin.Decode(multibaseKey);

        // Remove multicodec prefix and return public key
        return MulticodecHelper.RemoveEd25519Prefix(multicodecKey);
    }

    /// <summary>
    /// Creates a W3C DID Document (JSON-LD format)
    /// </summary>
    /// <param name="didIdentifier">The DID identifier</param>
    /// <param name="publicKey">Ed25519 public key</param>
    /// <returns>DID Document as JSON string</returns>
    private static string CreateDidDocument(string didIdentifier, byte[] publicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);
        ArgumentNullException.ThrowIfNull(publicKey);

        string publicKeyBase58 = SimpleBase.Base58.Bitcoin.Encode(publicKey);
        string verificationMethodId = $"{didIdentifier}#keys-1";

        DidDocument didDocument = new DidDocument
        {
            Context = new[]
            {
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = didIdentifier,
            VerificationMethod = new[]
            {
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Ed25519VerificationKey2020",
                    Controller = didIdentifier,
                    PublicKeyMultibase = $"z{publicKeyBase58}"
                }
            },
            Authentication = new[] { verificationMethodId }
        };

        return JsonSerializer.Serialize(didDocument, s_jsonOptions);
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
