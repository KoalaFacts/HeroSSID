using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Core.Interfaces;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.Interfaces;
using HeroSSID.DidOperations.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.DidOperations.Services;

/// <summary>
/// Service for creating W3C-compliant DIDs
/// Current: Uses simulated Ed25519 key generation and database storage
/// Future: Will use .NET 9 native Ed25519 and support did:web/did:key methods
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

            try
            {
                // Step 1: Generate Ed25519 key pair
                s_logGeneratingKeyPair(_logger, attempt, maxRetries, null);
                (byte[] publicKey, byte[] privateKey) = GenerateEd25519KeyPair();

                // Step 2: Generate DID identifier from public key
                s_logGeneratingDidIdentifier(_logger, null);
                string didIdentifier = GenerateDidIdentifier(publicKey);

                // Step 2a: Check for DID identifier collision
                bool didExists = await _dbContext.Dids
                    .AnyAsync(d => d.DidIdentifier == didIdentifier, cancellationToken).ConfigureAwait(false);

                if (didExists)
                {
                    s_logDidCollision(_logger, didIdentifier, attempt, maxRetries, null);

                    // Clear keys from memory before retrying
                    Array.Clear(publicKey, 0, publicKey.Length);
                    Array.Clear(privateKey, 0, privateKey.Length);

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
                byte[] encryptedPrivateKey = _keyEncryptionService.Encrypt(privateKey);

                // Clear private key from memory immediately after encryption
                Array.Clear(privateKey, 0, privateKey.Length);

                // Step 4: Create W3C DID Document
                s_logCreatingDidDocument(_logger, null);
                string didDocumentJson = CreateDidDocument(didIdentifier, publicKey);

                // Step 5: Create entity and save to database
                DateTimeOffset createdAt = DateTimeOffset.UtcNow;

                DidEntity didEntity = new DidEntity
                {
                    Id = Guid.NewGuid(),
                    TenantId = HeroDbContext.DefaultTenantId,
                    DidIdentifier = didIdentifier,
                    PublicKeyEd25519 = publicKey,
                    PrivateKeyEd25519Encrypted = encryptedPrivateKey,
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

                    // Clear public key from memory
                    Array.Clear(publicKey, 0, publicKey.Length);
                    Array.Clear(encryptedPrivateKey, 0, encryptedPrivateKey.Length);

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
                return new DidCreationResult
                {
                    Id = didEntity.Id,
                    TenantId = didEntity.TenantId,
                    DidIdentifier = didEntity.DidIdentifier,
                    PublicKey = didEntity.PublicKeyEd25519,
                    EncryptedPrivateKey = didEntity.PrivateKeyEd25519Encrypted,
                    DidDocumentJson = didEntity.DidDocumentJson,
                    Status = didEntity.Status,
                    CreatedAt = didEntity.CreatedAt
                };
            }
            catch (Exception ex) when (attempt >= maxRetries ||
                                        (ex is not InvalidOperationException && ex is not DbUpdateException))
            {
                s_logDidCreationFailed(_logger, attempt, ex);
                throw;
            }
        }

        // This should never be reached, but added for completeness
        throw new InvalidOperationException("Failed to create DID: unexpected end of retry loop");
    }

    /// <summary>
    /// Generates an Ed25519 key pair for signing
    /// MVP: Uses cryptographically secure random bytes to simulate Ed25519 keys
    /// v2: Use proper Ed25519 from WalletFramework or libsodium
    /// </summary>
    /// <returns>Tuple of (publicKey, privateKey)</returns>
    private static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
    {
        // For MVP, generate 32-byte keys using cryptographically secure random number generator
        // This is NOT actual Ed25519 key generation, but sufficient for MVP testing
        // v2: Replace with proper Ed25519 from WalletFramework SDK or libsodium

        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[32];

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(publicKey);
            rng.GetBytes(privateKey);
        }

        return (publicKey, privateKey);
    }

    /// <summary>
    /// Generates a DID identifier from a public key
    /// Format: did:key:z{multibase-multicodec-publicKey}
    /// MVP: Simplified did:key format
    /// Future: Proper multibase/multicodec encoding for full did:key spec
    /// </summary>
    /// <param name="publicKey">Ed25519 public key</param>
    /// <returns>DID identifier</returns>
    private static string GenerateDidIdentifier(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Public key must be 32 bytes for Ed25519", nameof(publicKey));
        }

        // For MVP, use simplified did:key format
        // did:key uses multibase (z = base58btc) + multicodec (0xed01 for Ed25519-pub) + public key
        // For now, we'll use a simplified version with just base58 encoding
        string base58PublicKey = ConvertToBase58(publicKey);

        return $"did:key:z6M{base58PublicKey}";
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

        string publicKeyBase58 = ConvertToBase58(publicKey);
        string verificationMethodId = $"{didIdentifier}#keys-1";

        var didDocument = new
        {
            id = didIdentifier,
            verificationMethod = new[]
            {
                new
                {
                    id = verificationMethodId,
                    type = "Ed25519VerificationKey2020",
                    controller = didIdentifier,
                    publicKeyBase58 = publicKeyBase58
                }
            },
            authentication = new[] { verificationMethodId }
        };

        return JsonSerializer.Serialize(didDocument, s_jsonOptions);
    }

    /// <summary>
    /// Converts bytes to Base58 encoding (Bitcoin alphabet)
    /// MVP: Simplified implementation
    /// v2: Use proper Base58 library
    /// </summary>
    /// <param name="data">Data to encode</param>
    /// <returns>Base58-encoded string</returns>
    private static string ConvertToBase58(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        const string base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // MVP: Simple hex-like encoding using Base58 characters
        // This is NOT proper Base58 encoding, but sufficient for MVP testing
        // v2: Replace with proper Base58 encoding library

        StringBuilder result = new StringBuilder();

        foreach (byte b in data)
        {
            // Map each byte to Base58 characters
            result.Append(base58Alphabet[b % base58Alphabet.Length]);
            result.Append(base58Alphabet[(b / base58Alphabet.Length) % base58Alphabet.Length]);
        }

        return result.ToString();
    }
}
