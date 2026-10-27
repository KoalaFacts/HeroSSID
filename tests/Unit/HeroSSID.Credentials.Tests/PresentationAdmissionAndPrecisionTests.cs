using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class PresentationAdmissionAndPrecisionTests : IDisposable
{
    private const string Audience = "https://verifier.example/precision";
    private readonly HeroDbContext _db;
    private readonly InMemoryRateLimiter _limiter = new();
    private readonly Tenant _issuerTenant = new(Guid.NewGuid());
    private readonly Tenant _holderTenant = new(Guid.NewGuid());
    private readonly Tenant _verifierTenant = new(Guid.NewGuid());
    private readonly Clock _clock = new();
    private readonly CountingStore _store;
    private readonly DidEntity _issuer;
    private readonly DidEntity _holder;
    private readonly byte[] _issuerKey;
    private readonly byte[] _holderKey;

    public PresentationAdmissionAndPrecisionTests()
    {
        _db = new HeroDbContext(new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        (_issuer, _issuerKey) = Identity(_issuerTenant, "did:web:precision-issuer.example");
        (_holder, _holderKey) = Identity(_holderTenant, "did:web:precision-holder.example");
        _db.Dids.AddRange(_issuer, _holder);
        _db.SaveChanges();
        _store = new CountingStore(new InMemoryPresentationChallengeStore(_clock));
    }

    [Fact]
    public async Task OneSecondProofRemainsUsableAfterCrossingASecondBoundary()
    {
        _clock.Advance(TimeSpan.FromMilliseconds(999));
        var service = Service();
        var challenge = service.CreateChallenge(_verifierTenant, Audience, _issuer.DidIdentifier, TimeSpan.FromSeconds(1));
        var proof = await service.CreatePresentationAsync(_holderTenant, Credential(), _holder.Id, challenge).ConfigureAwait(true);
        _clock.Advance(TimeSpan.FromMilliseconds(500));
        var result = await service.VerifyPresentationAsync(_verifierTenant, proof.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true);
        Assert.True(result.IsValid, string.Join(";", result.ValidationErrors));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(proof.PresentationJwt));
        var expected = (challenge.ExpiresAt.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / (decimal)TimeSpan.TicksPerSecond;
        Assert.Equal(expected, payload.RootElement.GetProperty("exp").GetDecimal());
    }

    [Fact]
    public async Task ExpiryDuringStoreConsumptionCannotReturnVerifiedIdentity()
    {
        var service = Service();
        var challenge = service.CreateChallenge(_verifierTenant, Audience, _issuer.DidIdentifier);
        var proof = await service.CreatePresentationAsync(_holderTenant, Credential(lifetimeSeconds: 1), _holder.Id, challenge).ConfigureAwait(true);
        _store.BeforeConsume = () => _clock.Advance(TimeSpan.FromSeconds(2));
        var result = await service.VerifyPresentationAsync(_verifierTenant, proof.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true);
        Assert.False(result.IsValid);
        Assert.Null(result.DisclosedClaims);
        Assert.Null(result.HolderDid);
        Assert.Null(result.IssuerDids);
        Assert.False(_store.TryConsume(_verifierTenant.GetCurrentTenantId(), Audience, challenge.Nonce));
    }

    [Fact]
    public void ChallengeIssuanceReservesVerifierQuotaBeforeStoreWork()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = Service(limiter);
        Assert.NotNull(service.CreateChallenge(_verifierTenant, Audience, _issuer.DidIdentifier));
        Assert.Throws<InvalidOperationException>(() => service.CreateChallenge(_verifierTenant, Audience, _issuer.DidIdentifier));
        Assert.Equal(1, _store.Issues);
        Assert.NotNull(service.CreateChallenge(new Tenant(Guid.NewGuid()), Audience, _issuer.DidIdentifier));
        Assert.Equal(2, _store.Issues);
    }

    [Fact]
    public async Task UnknownChallengeAttemptsSpendOnlyRequestersQuotaBeforeLookup()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = Service(limiter);
        var nonce = Base64UrlEncoder.Encode(new byte[32]);
        var rejected = await service.VerifyPresentationAsync(_verifierTenant, "malformed", Audience, nonce).ConfigureAwait(true);
        Assert.False(rejected.IsValid);
        Assert.False(await limiter.IsAllowedAsync(_verifierTenant.GetCurrentTenantId(), "PRESENTATION_VERIFY").ConfigureAwait(true));
        var finds = _store.Finds;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.VerifyPresentationAsync(_verifierTenant, "malformed", Audience, nonce)).ConfigureAwait(true);
        Assert.Equal(finds, _store.Finds);
        Assert.True(await limiter.IsAllowedAsync(_issuerTenant.GetCurrentTenantId(), "PRESENTATION_VERIFY").ConfigureAwait(true));
    }

    [Theory]
    [InlineData("audience")]
    [InlineData("nonce")]
    [InlineData("presentation")]
    public async Task InvalidBoundedInputsCannotReachChallengeLookup(string invalidPart)
    {
        var audience = invalidPart == "audience" ? new string('x', 2049) : Audience;
        var nonce = invalidPart == "nonce" ? new string('!', 43) : Base64UrlEncoder.Encode(new byte[32]);
        var token = invalidPart == "presentation" ? new string('x', 131073) : "malformed";
        var result = await Service().VerifyPresentationAsync(_verifierTenant, token, audience, nonce).ConfigureAwait(true);
        Assert.False(result.IsValid);
        Assert.Null(result.DisclosedClaims);
        Assert.Equal(0, _store.Finds);
    }

    private VerifiablePresentationService Service(IRateLimiter? limiter = null) => new(
        _db, new CredentialVerificationService(_db, limiter ?? _limiter, timeProvider: _clock), limiter ?? _limiter,
        new CopyEncryption(), _store, _clock);

    private string Credential(int lifetimeSeconds = 120) => Ed25519JwtSigner.CreateSignedJwt(
        "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
        JsonSerializer.Serialize(new
        {
            iss = _issuer.DidIdentifier, sub = _holder.DidIdentifier,
            iat = _clock.GetUtcNow().ToUnixTimeSeconds(),
            exp = _clock.GetUtcNow().AddSeconds(lifetimeSeconds).ToUnixTimeSeconds(),
            vc = new { credentialSubject = new { id = _holder.DidIdentifier, role = "member" } }
        }), _issuerKey);

    private static (DidEntity Identity, byte[] Key) Identity(ITenantContext tenant, string did)
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var privateKey = key.Export(KeyBlobFormat.RawPrivateKey)[..32];
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        return (new DidEntity
        {
            Id = Guid.NewGuid(), TenantId = tenant.GetCurrentTenantId(), DidIdentifier = did,
            PublicKeyEd25519 = publicKey, KeyFingerprint = SHA256.HashData(publicKey),
            PrivateKeyEd25519Encrypted = privateKey.ToArray(), DidDocumentJson = "{}", Status = "active", CreatedAt = DateTimeOffset.UtcNow
        }, privateKey);
    }

    public void Dispose()
    {
        _db.Dispose();
        _limiter.Dispose();
        CryptographicOperations.ZeroMemory(_issuerKey);
        CryptographicOperations.ZeroMemory(_holderKey);
        CryptographicOperations.ZeroMemory(_issuer.PrivateKeyEd25519Encrypted);
        CryptographicOperations.ZeroMemory(_holder.PrivateKeyEd25519Encrypted);
    }

    private sealed class Tenant(Guid id) : ITenantContext
    {
        public Guid GetCurrentTenantId() => id;
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }

    private sealed class CopyEncryption : IKeyEncryptionService
    {
        public byte[] Encrypt(byte[] plaintext) => plaintext.ToArray();
        public byte[] Decrypt(byte[] ciphertext) => ciphertext.ToArray();
        public string EncryptString(string plaintext) => plaintext;
        public string DecryptString(string ciphertext) => ciphertext;
    }

    private sealed class CountingStore(IPresentationChallengeStore inner) : IPresentationChallengeStore
    {
        public int Issues { get; private set; }
        public int Finds { get; private set; }
        public Action? BeforeConsume { get; set; }
        public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
        {
            Issues++;
            return inner.Issue(verifierTenantId, audience, trustedIssuerDid, lifetime);
        }
        public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce)
        {
            Finds++;
            return inner.Find(verifierTenantId, audience, nonce);
        }
        public bool TryConsume(Guid verifierTenantId, string audience, string nonce)
        {
            BeforeConsume?.Invoke();
            return inner.TryConsume(verifierTenantId, audience, nonce);
        }
    }
}
