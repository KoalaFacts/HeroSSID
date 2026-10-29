using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class RevocationSnapshotFreshnessTests
{
    private static readonly DateTimeOffset ObservationTime =
        new(2026, 10, 29, 7, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task DelayedKeyDecryptionMustNotRenewSnapshotObservationWindow()
    {
        var (service, issuer, context, db) = await CreateServiceAsync(TimeSpan.FromSeconds(45)).ConfigureAwait(true);
        await using (db)
        {
            string? snapshot = await service.ExportAsync(context, issuer, CancellationToken.None).ConfigureAwait(true);
            Assert.NotNull(snapshot);
            using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(snapshot));
            Assert.Equal(ObservationTime.ToUnixTimeSeconds(),
                payload.RootElement.GetProperty("iat").GetInt64());
            Assert.Equal(ObservationTime.AddSeconds(60).ToUnixTimeSeconds(),
                payload.RootElement.GetProperty("exp").GetInt64());
        }
    }

    [Fact]
    public async Task ExhaustedObservationWindowMustNotProduceSignedSnapshot()
    {
        var (service, issuer, context, db) = await CreateServiceAsync(TimeSpan.FromSeconds(65)).ConfigureAwait(true);
        await using (db)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.ExportAsync(context, issuer, CancellationToken.None)).ConfigureAwait(true);
        }
    }

    private static async Task<(IssuerRevocationSnapshotService Service, string Did,
        ITenantContext Context, HeroDbContext Db)> CreateServiceAsync(TimeSpan signingDelay)
    {
        var clock = new AdjustableClock(ObservationTime);
        var tenantId = Guid.NewGuid();
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        string did = new DidKeyMethod().GenerateDidIdentifier(publicKey);

        var options = new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var db = new HeroDbContext(options);
        db.Dids.Add(new DidEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            DidIdentifier = did,
            PublicKeyEd25519 = publicKey,
            KeyFingerprint = SHA256.HashData(publicKey),
            PrivateKeyEd25519Encrypted = [1],
            DidDocumentJson = "{}",
            CreatedAt = ObservationTime
        });
        await db.SaveChangesAsync().ConfigureAwait(true);
        var service = new IssuerRevocationSnapshotService(
            db, new DelayedDecryptor(privateKey, clock, signingDelay),
            new PermissiveLimiter(), clock);
        return (service, did, new FixedTenant(tenantId), db);
    }

    private sealed class AdjustableClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class DelayedDecryptor(byte[] key, AdjustableClock clock, TimeSpan delay) : IKeyEncryptionService
    {
        public byte[] Decrypt(byte[] ciphertext)
        {
            clock.Advance(delay);
            return (byte[])key.Clone();
        }

        public byte[] Encrypt(byte[] plaintext) => throw new NotSupportedException();
        public string EncryptString(string plaintext) => throw new NotSupportedException();
        public string DecryptString(string ciphertext) => throw new NotSupportedException();
    }

    private sealed class FixedTenant(Guid id) : ITenantContext
    {
        public Guid GetCurrentTenantId() => id;
    }

    private sealed class PermissiveLimiter : IRateLimiter
    {
        public Task<bool> TryAcquireAsync(Guid tenantId, string operationType,
            CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task<bool> IsAllowedAsync(Guid tenantId, string operationType,
            CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task RecordOperationAsync(Guid tenantId, string operationType,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
