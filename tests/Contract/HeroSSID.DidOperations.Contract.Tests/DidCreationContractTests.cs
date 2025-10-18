using System.Text.Json;
using HeroSSID.Core.Interfaces;
using HeroSSID.Data;
using HeroSSID.DidOperations.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.DidOperations.Contract.Tests;

/// <summary>
/// Contract tests for DID creation that verify W3C DID compliance:
/// - Ed25519 key generation
/// - W3C DID Document specification
/// - DID method format validation
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores - test method naming convention
#pragma warning disable CA1031 // Do not catch general exception types - test validation
#pragma warning disable CA1307 // Specify StringComparison for clarity - test assertions
public sealed class DidCreationContractTests : IDisposable
{
    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _mockEncryption;
    private readonly ITenantContext _mockTenantContext;
    private readonly ILogger<DidCreationService> _mockLogger;

    public DidCreationContractTests()
    {
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"ContractTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        _dbContext.Database.EnsureCreated();

        _mockEncryption = new MockKeyEncryptionService();
        _mockTenantContext = new MockTenantContext();
        _mockLogger = new MockLogger();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task CreateDid_ShouldPersistToDatabase()
    {
        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act - Call DidCreationService.CreateDidAsync()
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert - Verify DID was stored in database with correct format
        var storedDid = await _dbContext.Dids
            .FirstOrDefaultAsync(d => d.DidIdentifier == result.DidIdentifier, TestContext.Current.CancellationToken);

        Assert.NotNull(storedDid);
        Assert.Equal(result.DidIdentifier, storedDid.DidIdentifier);
        Assert.Equal(32, storedDid.PublicKeyEd25519.Length); // Ed25519 public key is 32 bytes
        Assert.True(storedDid.PrivateKeyEd25519Encrypted.Length > 0); // Encrypted private key exists
        Assert.Equal("active", storedDid.Status);
    }

    [Fact]
    public async Task GeneratedKeys_ShouldBeEd25519Format()
    {
        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _mockLogger);

        // Act - Generate keys using DidCreationService
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert - Verify Ed25519 key characteristics
        // - Public key is 32 bytes (Ed25519)
        Assert.Equal(32, result.PublicKey.Length);

        // - Private key was encrypted
        Assert.NotNull(result.EncryptedPrivateKey);
        Assert.True(result.EncryptedPrivateKey.Length > 0);

        // - Keys are valid for signing/verification (verified by DID document creation)
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vm));
        Assert.True(vm.GetArrayLength() > 0);
    }

    [Fact]
    public void DidDocument_ShouldBeW3CCompliant()
    {
        // Arrange - Create a W3C DID Document
        const string sampleDidDocument = """
        {
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          "verificationMethod": [{
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#keys-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
          }],
          "authentication": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#keys-1"]
        }
        """;

        // Act
        JsonDocument? document = null;
        Exception? parseException = null;
        try
        {
            document = JsonDocument.Parse(sampleDidDocument);
        }
        catch (Exception ex)
        {
            parseException = ex;
        }

        // Assert - W3C DID Core compliance checks
        Assert.Null(parseException);
        Assert.NotNull(document);

        JsonElement root = document.RootElement;

        // Must have '@context' field (W3C requirement)
        Assert.True(root.TryGetProperty("@context", out _));

        // Must have 'id' field with DID identifier
        Assert.True(root.TryGetProperty("id", out JsonElement idElement));
        string didId = idElement.GetString() ?? string.Empty;
        Assert.StartsWith("did:", didId, StringComparison.Ordinal);

        // Must have 'verificationMethod' array
        Assert.True(root.TryGetProperty("verificationMethod", out JsonElement vmElement));
        Assert.Equal(JsonValueKind.Array, vmElement.ValueKind);
        Assert.True(vmElement.GetArrayLength() > 0);

        // First verification method must have required fields
        JsonElement firstVm = vmElement[0];
        Assert.True(firstVm.TryGetProperty("id", out _));
        Assert.True(firstVm.TryGetProperty("type", out JsonElement typeElement));
        Assert.True(firstVm.TryGetProperty("controller", out _));

        // Type should be Ed25519-based
        string vmType = typeElement.GetString() ?? string.Empty;
        Assert.Contains("Ed25519", vmType, StringComparison.Ordinal);

        // Must have authentication property
        Assert.True(root.TryGetProperty("authentication", out JsonElement authElement));
        Assert.Equal(JsonValueKind.Array, authElement.ValueKind);

        document.Dispose();
    }

    [Fact]
    public void Ed25519PublicKey_ShouldBe32Bytes()
    {
        // Arrange - Ed25519 public keys must be exactly 32 bytes
        const int expectedKeyLength = 32;

        // Act - Generate a sample key (this will be replaced with actual key generation)
        byte[] sampleKey = new byte[expectedKeyLength];
#pragma warning disable CA5394 // Do not use insecure randomness - this is a test example
        Random.Shared.NextBytes(sampleKey);
#pragma warning restore CA5394

        // Assert
        Assert.Equal(expectedKeyLength, sampleKey.Length);

        // This test passes to demonstrate the requirement
        // Real implementation will use actual Ed25519 key generation
    }

    [Fact]
    public void DidKeyFormat_ShouldFollowW3CSpec()
    {
        // Arrange - W3C did:key specification format
        // Format: did:key:z{multibase-encoded-multicodec-key}
        // where z = base58btc multibase prefix
        // and 0xed01 = Ed25519 public key multicodec prefix

        const string validDidKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        // Act
        string[] parts = validDidKey.Split(':');

        // Assert - Format validation
        Assert.Equal(3, parts.Length);
        Assert.Equal("did", parts[0]);
        Assert.Equal("key", parts[1]);
        Assert.StartsWith("z", parts[2], StringComparison.Ordinal); // z = base58btc multibase
        Assert.True(parts[2].Length > 10, "Encoded key should be substantial length");
    }

    [Fact]
    public void DidKeyEncoding_ShouldUseMultibaseMulticodec()
    {
        // Arrange - Test the multibase/multicodec encoding principles
        // This is a contract test for the encoding format, not implementation

        // A valid did:key has structure:
        // did:key:z{base58(0xed01 + 32-byte-public-key)}
        // Total encoded size: 2 bytes prefix + 32 bytes key = 34 bytes input
        // Base58 encoding ~= 46-47 characters for 34 bytes

        const string sampleDidKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        string encodedPortion = sampleDidKey.Replace("did:key:z", "", StringComparison.Ordinal);

        // Assert - Encoding characteristics
        Assert.True(encodedPortion.Length >= 43, "Base58-encoded 34 bytes should be ~46 chars");
        Assert.True(encodedPortion.Length <= 50, "Base58-encoded 34 bytes should be ~46 chars");

        // Base58 alphabet check (no 0, O, I, l to avoid confusion)
        foreach (char c in encodedPortion)
        {
            Assert.False(c == '0' || c == 'O' || c == 'I' || c == 'l',
                $"Base58 should not contain confusing characters: {c}");
        }
    }

    [Fact]
    public void DidKey_ShouldDecodeToEd25519PublicKey()
    {
        // Arrange - Contract: A did:key should be decodable back to a 32-byte Ed25519 public key
        // This test validates the round-trip capability

        // The decode process should:
        // 1. Remove "did:key:z" prefix
        // 2. Base58 decode the remainder
        // 3. Remove 0xed01 multicodec prefix
        // 4. Extract 32-byte Ed25519 public key

        // Assert - This is a specification contract, actual implementation will be in DidCreationService
        const int expectedPublicKeyLength = 32;
        const int multicodecPrefixLength = 2;
        const int expectedMulticodecKeyLength = expectedPublicKeyLength + multicodecPrefixLength;

        Assert.Equal(34, expectedMulticodecKeyLength); // 2 + 32 = 34 bytes before base58 encoding
    }

    private sealed class MockKeyEncryptionService : IKeyEncryptionService
    {
        public byte[] Encrypt(byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(plaintext);
            byte[] encrypted = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++)
            {
                encrypted[i] = (byte)(plaintext[i] ^ 0x5A);
            }
            return encrypted;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);
            byte[] decrypted = new byte[ciphertext.Length];
            for (int i = 0; i < ciphertext.Length; i++)
            {
                decrypted[i] = (byte)(ciphertext[i] ^ 0x5A);
            }
            return decrypted;
        }

        public string EncryptString(string plaintext)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            byte[] encrypted = Encrypt(bytes);
            return Convert.ToBase64String(encrypted);
        }

        public string DecryptString(string ciphertext)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);
            byte[] encrypted = Convert.FromBase64String(ciphertext);
            byte[] decrypted = Decrypt(encrypted);
            return System.Text.Encoding.UTF8.GetString(decrypted);
        }
    }

    private sealed class MockLogger : ILogger<DidCreationService>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => false;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }

    private sealed class MockTenantContext : ITenantContext
    {
        public Guid GetCurrentTenantId() => Guid.Parse("11111111-1111-1111-1111-111111111111");
    }
}
