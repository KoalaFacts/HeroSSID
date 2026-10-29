using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSec.Cryptography;
using NSubstitute;

namespace HeroSSID.DidOperations.Tests;

// These test the locally authenticated, explicitly requested compatibility view,
// not remote DID resolution or independent-wallet interoperability.
#pragma warning disable CA1707 // xUnit method naming convention
public sealed class CanonicalDidResolutionTests
{
    [Fact]
    public async Task CanonicalView_UsesStoredPublicKey_NotLegacyDocumentAndNeverUpdatesDatabase()
    {
        await using var db = CreateDatabase();
        var (did, entity) = AddRecord(db);
        string legacy = entity.DidDocumentJson;
        var service = CreateService(db, entity.TenantId);

        var current = await service.ResolveCanonicalDidKeyAsync(did, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(current.IsSuccess);
        Assert.NotNull(current.DidDocument);
        using var parsed = JsonDocument.Parse(current.DidDocument);
        string methodId = did + "#" + did["did:key:".Length..];
        Assert.Equal(did, parsed.RootElement.GetProperty("id").GetString());
        Assert.Equal(methodId, parsed.RootElement.GetProperty("verificationMethod")[0].GetProperty("id").GetString());
        Assert.Equal(did["did:key:".Length..],
            parsed.RootElement.GetProperty("verificationMethod")[0].GetProperty("publicKeyMultibase").GetString());
        Assert.Equal(methodId, parsed.RootElement.GetProperty("authentication")[0].GetString());
        Assert.Equal(methodId, parsed.RootElement.GetProperty("assertionMethod")[0].GetString());

        var old = await service.ResolveAsync(did, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(legacy, old.DidDocument);
        Assert.Equal(legacy, entity.DidDocumentJson);
        Assert.DoesNotContain(db.ChangeTracker.Entries(), entry => entry.State == EntityState.Modified);
    }

    [Fact]
    public async Task CanonicalView_RejectsStoredPublicKeyMismatchInsteadOfAttestingTheWrongKey()
    {
        await using var db = CreateDatabase();
        var (did, entity) = AddRecord(db);
        entity.PublicKeyEd25519 = new byte[32];
        await db.SaveChangesAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);

        var result = await CreateService(db, entity.TenantId).ResolveCanonicalDidKeyAsync(did, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.False(result.IsSuccess);
        Assert.Null(result.DidDocument);
        Assert.Equal("invalidDid", result.Metadata.Error);
    }

    [Fact]
    public async Task CanonicalView_DoesNotExposeRecordsFromAnotherTenant()
    {
        await using var db = CreateDatabase();
        var (did, entity) = AddRecord(db);
        var result = await CreateService(db, Guid.NewGuid()).ResolveCanonicalDidKeyAsync(did, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.False(result.IsSuccess);
        Assert.Null(result.DidDocument);
        Assert.Equal("notFound", result.Metadata.Error);
        Assert.NotEqual(Guid.Empty, entity.TenantId);
    }

    [Fact]
    public async Task CanonicalView_DoesNotPublishDeactivatedDid()
    {
        await using var db = CreateDatabase();
        var (did, entity) = AddRecord(db);
        entity.Status = "deactivated";
        await db.SaveChangesAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        var result = await CreateService(db, entity.TenantId).ResolveCanonicalDidKeyAsync(did, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.False(result.IsSuccess);
        Assert.Null(result.DidDocument);
        Assert.Equal("notFound", result.Metadata.Error);
    }

    private static HeroDbContext CreateDatabase()
    {
        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase("canonical-did-" + Guid.NewGuid()).Options;
        return new HeroDbContext(options);
    }

    private static (string Did, DidEntity Entity) AddRecord(HeroDbContext db)
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var did = new DidKeyMethod().GenerateDidIdentifier(publicKey);
        var entity = new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            DidIdentifier = did,
            PublicKeyEd25519 = publicKey,
            KeyFingerprint = new byte[32],
            PrivateKeyEd25519Encrypted = new byte[32],
            DidDocumentJson = "{\"id\":\"" + did + "\",\"verificationMethod\":[{\"id\":\"" + did + "#keys-1\"}]}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.Dids.Add(entity);
        db.SaveChanges();
        return (did, entity);
    }

    private static DidResolutionService CreateService(HeroDbContext db, Guid tenantId)
    {
        var tenant = Substitute.For<ITenantContext>();
        tenant.GetCurrentTenantId().Returns(tenantId);
        var resolver = new DidMethodResolver(new IDidMethod[] { new DidKeyMethod() });
        return new DidResolutionService(db, tenant, resolver, NullLogger<DidResolutionService>.Instance);
    }
}
#pragma warning restore CA1707
