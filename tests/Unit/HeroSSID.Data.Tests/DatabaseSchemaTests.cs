using System.Text.Json;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Data.Tests;

/// <summary>
/// Tests for database schema validation and JSON storage
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores
public sealed class DatabaseSchemaTests : IDisposable
{
    private readonly HeroDbContext _dbContext;

    public DatabaseSchemaTests()
    {
        DbContextOptions<HeroDbContext> options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(databaseName: $"SchemaTest_{Guid.NewGuid()}")
            .Options;

        _dbContext = new HeroDbContext(options);
        _dbContext.Database.EnsureCreated();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task DidDocument_WithAtContext_ShouldStoreAndRetrieveCorrectly()
    {
        // Arrange - Create a W3C-compliant DID document JSON string with @context
        string didDocumentJson = """
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
          ],
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          "verificationMethod": [
            {
              "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#keys-1",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }
          ],
          "authentication": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#keys-1"]
        }
        """;

        var pubKey = new byte[32];

        DidEntity didEntity = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            PublicKeyEd25519 = pubKey,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(pubKey),
            PrivateKeyEd25519Encrypted = new byte[32],
            DidDocumentJson = didDocumentJson,
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Act - Store in database
        _dbContext.Dids.Add(didEntity);
        await _dbContext.SaveChangesAsync();

        // Retrieve from database
        DidEntity? retrieved = await _dbContext.Dids
            .FirstOrDefaultAsync(d => d.DidIdentifier == didEntity.DidIdentifier);

        // Assert
        Assert.NotNull(retrieved);

        // Verify the JSON can be parsed and contains @context
        using var doc = JsonDocument.Parse(retrieved.DidDocumentJson);
        Assert.True(doc.RootElement.TryGetProperty("@context", out var contextProp));
        Assert.Equal(JsonValueKind.Array, contextProp.ValueKind);

        // Verify @context contains required W3C DID v1
        bool hasDidV1 = false;
        foreach (var element in contextProp.EnumerateArray())
        {
            if (element.GetString() == "https://www.w3.org/ns/did/v1")
            {
                hasDidV1 = true;
                break;
            }
        }
        Assert.True(hasDidV1);
    }

    [Fact]
    public async Task DidDocument_WithComplexJson_ShouldPreserveStructure()
    {
        // Arrange - Create DID document with multiple verification methods and services
        string complexDidDocJson = """
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://didcomm.org/messaging/contexts/v2"
          ],
          "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
          "verificationMethod": [
            {
              "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#keys-1",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
              "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }
          ],
          "authentication": ["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#keys-1"],
          "assertionMethod": ["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#keys-1"],
          "service": [
            {
              "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#didcomm",
              "type": "DIDCommMessaging",
              "serviceEndpoint": "https://example.com/endpoint"
            }
          ]
        }
        """;

        var pubKey2 = new byte[32];

        DidEntity didEntity = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = HeroDbContext.DefaultTenantId,
            DidIdentifier = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            PublicKeyEd25519 = pubKey2,
            KeyFingerprint = System.Security.Cryptography.SHA256.HashData(pubKey2),
            PrivateKeyEd25519Encrypted = new byte[32],
            DidDocumentJson = complexDidDocJson,
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Act
        _dbContext.Dids.Add(didEntity);
        await _dbContext.SaveChangesAsync();

        DidEntity? retrieved = await _dbContext.Dids
            .FirstOrDefaultAsync(d => d.DidIdentifier == didEntity.DidIdentifier);

        // Assert
        Assert.NotNull(retrieved);

        using var doc = JsonDocument.Parse(retrieved.DidDocumentJson);

        // Verify @context has all 3 entries
        Assert.True(doc.RootElement.TryGetProperty("@context", out var contextProp));
        Assert.Equal(3, contextProp.GetArrayLength());

        // Verify verificationMethod
        Assert.True(doc.RootElement.TryGetProperty("verificationMethod", out var vmProp));
        Assert.Equal(1, vmProp.GetArrayLength());

        // Verify authentication
        Assert.True(doc.RootElement.TryGetProperty("authentication", out var authProp));
        Assert.Equal(1, authProp.GetArrayLength());

        // Verify assertionMethod
        Assert.True(doc.RootElement.TryGetProperty("assertionMethod", out var assertProp));
        Assert.Equal(1, assertProp.GetArrayLength());

        // Verify service
        Assert.True(doc.RootElement.TryGetProperty("service", out var serviceProp));
        Assert.Equal(1, serviceProp.GetArrayLength());
    }

    [Fact]
    public void DbContext_DidDocumentJson_ShouldBeConfigured()
    {
        // Arrange & Act
        var entityType = _dbContext.Model.FindEntityType(typeof(DidEntity));

        // Assert
        Assert.NotNull(entityType);

        var didDocumentProperty = entityType.FindProperty("DidDocumentJson");
        Assert.NotNull(didDocumentProperty);

        // Verify it's required
        Assert.False(didDocumentProperty.IsNullable);

        // Verify column name mapping
        Assert.Equal("did_document_json", didDocumentProperty.GetColumnName());
    }
}
#pragma warning restore CA1707
