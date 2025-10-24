using System.Text.Json;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// W3C DID Core 1.0 Specification Compliance Tests
/// Reference: https://www.w3.org/TR/did-core/
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores
public sealed class W3cComplianceTests : IDisposable
{
    private readonly HeroDbContext _dbContext;
    private readonly IKeyEncryptionService _mockEncryption;
    private readonly ITenantContext _mockTenantContext;
    private readonly DidMethodResolver _didMethodResolver;
    private readonly ILogger<DidCreationService> _mockLogger;

    public W3cComplianceTests()
    {
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"W3cCompliance_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        _dbContext.Database.EnsureCreated();

        _mockEncryption = new MockKeyEncryptionService();
        _mockTenantContext = new MockTenantContext();
        _mockLogger = new MockLogger();

        // Setup DID method resolver with did:key and did:web implementations
        IDidMethod[] didMethods = new IDidMethod[]
        {
            new DidKeyMethod(),
            new DidWebMethod()
        };
        _didMethodResolver = new DidMethodResolver(didMethods);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task DidDocument_MustHaveContextProperty()
    {
        // W3C DID Core: DID documents MUST include the @context property
        // Reference: https://www.w3.org/TR/did-core/#contexts

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("@context", out var contextProp));
        Assert.Equal(JsonValueKind.Array, contextProp.ValueKind);
    }

    [Fact]
    public async Task DidDocument_ContextMustIncludeDidV1()
    {
        // W3C DID Core: The @context property MUST include the base DID context
        // Reference: https://www.w3.org/TR/did-core/#contexts

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("@context", out var contextProp));

        bool hasDidV1Context = false;
        foreach (var element in contextProp.EnumerateArray())
        {
            if (element.GetString() == "https://www.w3.org/ns/did/v1")
            {
                hasDidV1Context = true;
                break;
            }
        }

        Assert.True(hasDidV1Context, "DID document must include https://www.w3.org/ns/did/v1 in @context");
    }

    [Fact]
    public async Task DidDocument_MustHaveIdProperty()
    {
        // W3C DID Core: DID documents MUST have an id property
        // Reference: https://www.w3.org/TR/did-core/#did-subject

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("id", out var idProp));

        string? didId = idProp.GetString();
        Assert.NotNull(didId);
        Assert.StartsWith("did:", didId, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DidDocument_IdMustMatchDidSyntax()
    {
        // W3C DID Core: The id property must conform to DID syntax
        // Format: did:method:method-specific-id
        // Reference: https://www.w3.org/TR/did-core/#did-syntax

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("id", out var idProp));

        string? didId = idProp.GetString();
        Assert.NotNull(didId);

        // Verify DID syntax: did:method:method-specific-id
        string[] parts = didId.Split(':');
        Assert.True(parts.Length >= 3, "DID must have at least 3 parts separated by colons");
        Assert.Equal("did", parts[0]);
        Assert.NotEmpty(parts[1]); // method name
        Assert.NotEmpty(parts[2]); // method-specific-id
    }

    [Fact]
    public async Task VerificationMethod_MustHaveRequiredProperties()
    {
        // W3C DID Core: Verification methods MUST have id, type, controller properties
        // Reference: https://www.w3.org/TR/did-core/#verification-methods

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("id", out _), "Verification method must have 'id' property");
        Assert.True(firstVm.TryGetProperty("type", out _), "Verification method must have 'type' property");
        Assert.True(firstVm.TryGetProperty("controller", out _), "Verification method must have 'controller' property");
    }

    [Fact]
    public async Task VerificationMethod_IdMustBeAbsoluteUri()
    {
        // W3C DID Core: Verification method id must be an absolute URI
        // Reference: https://www.w3.org/TR/did-core/#verification-methods

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("id", out var idProp));

        string? vmId = idProp.GetString();
        Assert.NotNull(vmId);

        // Verification method ID should be absolute (contains did: or full URL)
        Assert.True(vmId.Contains("did:", StringComparison.Ordinal) || Uri.IsWellFormedUriString(vmId, UriKind.Absolute),
            "Verification method id must be an absolute URI");
    }

    [Fact]
    public async Task VerificationMethod_MustHavePublicKeyProperty()
    {
        // W3C DID Core: Verification methods MUST have a public key representation
        // Reference: https://www.w3.org/TR/did-core/#verification-material

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];

        // Must have at least one of: publicKeyMultibase, publicKeyJwk, publicKeyBase58 (deprecated)
        bool hasPublicKey = firstVm.TryGetProperty("publicKeyMultibase", out _) ||
                           firstVm.TryGetProperty("publicKeyJwk", out _) ||
                           firstVm.TryGetProperty("publicKeyBase58", out _);

        Assert.True(hasPublicKey, "Verification method must have a public key property (publicKeyMultibase, publicKeyJwk, etc.)");
    }

    [Fact]
    public async Task VerificationMethod_PublicKeyMultibaseMustHaveCorrectPrefix()
    {
        // W3C DID Core: publicKeyMultibase uses multibase encoding
        // 'z' prefix indicates base58btc encoding
        // Reference: https://www.w3.org/TR/did-spec-registries/#publickeyMultibase

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("publicKeyMultibase", out var pkProp));

        string? publicKey = pkProp.GetString();
        Assert.NotNull(publicKey);
        Assert.StartsWith("z", publicKey, StringComparison.Ordinal); // 'z' = base58btc
    }

    [Fact]
    public async Task VerificationMethod_TypeMustBeRecognized()
    {
        // W3C DID Core: Verification method type should be from registry
        // Reference: https://www.w3.org/TR/did-spec-registries/#verification-method-types

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("type", out var typeProp));

        string? vmType = typeProp.GetString();
        Assert.NotNull(vmType);

        // Known verification method types from W3C registry
        string[] recognizedTypes = new[]
        {
            "Ed25519VerificationKey2020",
            "Ed25519VerificationKey2018",
            "JsonWebKey2020",
            "EcdsaSecp256k1VerificationKey2019",
            "X25519KeyAgreementKey2019"
        };

        Assert.Contains(vmType, recognizedTypes);
    }

    [Fact]
    public async Task Authentication_MustReferenceVerificationMethod()
    {
        // W3C DID Core: Authentication can reference verification methods
        // Reference: https://www.w3.org/TR/did-core/#authentication

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);

        if (doc.RootElement.TryGetProperty("authentication", out var authArray))
        {
            Assert.True(authArray.GetArrayLength() > 0);

            // Get first authentication reference
            string? authRef = authArray[0].GetString();
            Assert.NotNull(authRef);

            // Verify it references a verification method
            Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
            Assert.True(vmArray.GetArrayLength() > 0);

            var firstVm = vmArray[0];
            Assert.True(firstVm.TryGetProperty("id", out var vmIdProp));
            string? vmId = vmIdProp.GetString();

            Assert.Equal(vmId, authRef);
        }
    }

    [Fact]
    public async Task DidDocument_MustBeValidJson()
    {
        // W3C DID Core: DID documents must be valid JSON
        // Reference: https://www.w3.org/TR/did-core/#json

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert - should not throw exception when parsing
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task DidDocument_MustNotContainDeprecatedProperties()
    {
        // Best practice: Should not use deprecated properties like publicKeyBase58
        // Prefer publicKeyMultibase instead

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];

        // Should NOT have deprecated publicKeyBase58
        Assert.False(firstVm.TryGetProperty("publicKeyBase58", out _),
            "Should use publicKeyMultibase instead of deprecated publicKeyBase58");
    }

    [Fact]
    public async Task DidDocument_ControllerMustMatchDidSubject()
    {
        // W3C DID Core: Controller should typically match the DID subject for self-controlled DIDs
        // Reference: https://www.w3.org/TR/did-core/#verification-methods

        // Arrange
        DidCreationService service = new DidCreationService(_dbContext, _mockEncryption, _mockTenantContext, _didMethodResolver, _mockLogger);

        // Act
        var result = await service.CreateDidAsync(TestContext.Current.CancellationToken);

        // Assert
        using var doc = JsonDocument.Parse(result.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("id", out var didIdProp));
        string? didId = didIdProp.GetString();
        Assert.NotNull(didId);

        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmArray));
        Assert.True(vmArray.GetArrayLength() > 0);

        var firstVm = vmArray[0];
        Assert.True(firstVm.TryGetProperty("controller", out var controllerProp));
        string? controller = controllerProp.GetString();

        Assert.Equal(didId, controller);
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
#pragma warning restore CA1707
