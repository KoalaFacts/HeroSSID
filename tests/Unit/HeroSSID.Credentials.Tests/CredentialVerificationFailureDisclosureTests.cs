using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>Rejected credentials must not publish identity fields as verification output.</summary>
public sealed class CredentialVerificationFailureDisclosureTests : IDisposable
{
    private const string IssuerDid = "did:example:failure-disclosure-issuer";
    private const string ClaimMarker = "untrusted-identity-must-not-escape";
    private static readonly Guid IssuerTenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid RequesterTenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private readonly HeroDbContext _dbContext;
    private readonly InMemoryRateLimiter _limiter = new();
    private readonly Key _issuerKey = Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    public CredentialVerificationFailureDisclosureTests()
    {
        _dbContext = new HeroDbContext(new DbContextOptionsBuilder<HeroDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
    }

    [Theory]
    [InlineData("signature", VerificationStatus.SignatureInvalid, false)]
    [InlineData("signature", VerificationStatus.SignatureInvalid, true)]
    [InlineData("expired", VerificationStatus.Expired, false)]
    [InlineData("expired", VerificationStatus.Expired, true)]
    [InlineData("unknown", VerificationStatus.IssuerNotFound, false)]
    [InlineData("unknown", VerificationStatus.IssuerNotFound, true)]
    [InlineData("deactivated", VerificationStatus.IssuerNotFound, false)]
    [InlineData("deactivated", VerificationStatus.IssuerNotFound, true)]
    [InlineData("revoked", VerificationStatus.Revoked, false)]
    [InlineData("revoked", VerificationStatus.Revoked, true)]
    [InlineData("malformed", VerificationStatus.MalformedJwt, false)]
    [InlineData("malformed", VerificationStatus.MalformedJwt, true)]
    public async Task RejectedCredentialReturnsNoIdentityFields(
        string scenario, VerificationStatus expectedStatus, bool explicitIssuerTenant)
    {
        var expiresAt = DateTimeOffset.UtcNow.AddDays(scenario == "expired" ? -1 : 1);
        var credential = SignCredential(expiresAt.ToUnixTimeSeconds());
        if (scenario != "unknown")
        {
            var issuer = await EnrollIssuerAsync(scenario == "deactivated").ConfigureAwait(true);
            if (scenario == "revoked")
            {
                _dbContext.VerifiableCredentials.Add(new VerifiableCredentialEntity
                {
                    Id = Guid.NewGuid(), TenantId = IssuerTenantId,
                    IssuerDidId = issuer.Id, HolderDidId = issuer.Id,
                    CredentialType = "TestCredential", CredentialJwt = credential,
                    Status = "revoked", IssuedAt = DateTimeOffset.UtcNow.AddDays(-2),
                    RevokedAt = DateTimeOffset.UtcNow
                });
                await _dbContext.SaveChangesAsync().ConfigureAwait(true);
            }
        }

        if (scenario == "signature")
        {
            // Keep the complete, correctly encoded payload but invalidate a real signature byte.
            var parts = credential.Split('.');
            var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
            signature[0] ^= 1;
            credential = $"{parts[0]}.{parts[1]}.{Base64UrlEncoder.Encode(signature)}";
        }
        else if (scenario == "malformed")
        {
            credential = "not.a.valid.jwt.format";
        }

        var result = await VerifyAsync(credential, explicitIssuerTenant).ConfigureAwait(true);

        Assert.False(result.IsValid);
        Assert.Equal(expectedStatus, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
        Assert.Null(result.CredentialSubject);
        Assert.Null(result.IssuerDid);
        Assert.Null(result.ExpiresAt);
        var serialized = JsonSerializer.Serialize(result);
        Assert.DoesNotContain(ClaimMarker, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(IssuerDid, serialized, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ValidCredentialStillReturnsVerifiedFields(bool explicitIssuerTenant, bool hasExpiration)
    {
        await EnrollIssuerAsync(false).ConfigureAwait(true);
        long? expiration = hasExpiration ? DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds() : null;
        var result = await VerifyAsync(SignCredential(expiration), explicitIssuerTenant).ConfigureAwait(true);

        Assert.True(result.IsValid);
        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Empty(result.ValidationErrors);
        Assert.Equal(IssuerDid, result.IssuerDid);
        Assert.NotNull(result.CredentialSubject);
        Assert.Equal(ClaimMarker, Assert.IsType<JsonElement>(result.CredentialSubject["marker"]).GetString());
        var degree = Assert.IsType<JsonElement>(result.CredentialSubject["degree"]);
        Assert.Equal("Bachelor", degree.GetProperty("name").GetString());
        Assert.Equal(expiration.HasValue ? DateTimeOffset.FromUnixTimeSeconds(expiration.Value) : (DateTimeOffset?)null,
            result.ExpiresAt);
    }

    private Task<CredentialVerificationResult> VerifyAsync(string credential, bool explicitIssuerTenant)
    {
        var service = new CredentialVerificationService(_dbContext, _limiter);
        return explicitIssuerTenant
            ? service.VerifyCredentialFromIssuerAsync(new TenantContext(RequesterTenantId), IssuerTenantId, credential)
            : service.VerifyCredentialAsync(new TenantContext(IssuerTenantId), credential);
    }

    private async Task<DidEntity> EnrollIssuerAsync(bool deactivated)
    {
        var publicKey = _issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var issuer = new DidEntity
        {
            Id = Guid.NewGuid(), TenantId = IssuerTenantId, DidIdentifier = IssuerDid,
            PublicKeyEd25519 = publicKey, KeyFingerprint = SHA256.HashData(publicKey),
            PrivateKeyEd25519Encrypted = new byte[64], DidDocumentJson = "{}",
            Status = deactivated ? "deactivated" : "active", CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.Dids.Add(issuer);
        await _dbContext.SaveChangesAsync().ConfigureAwait(true);
        return issuer;
    }

    private string SignCredential(long? expiration)
    {
        var header = JsonSerializer.Serialize(new { typ = "vc+jwt", alg = "EdDSA" });
        var payload = JsonSerializer.Serialize(new
        {
            iss = IssuerDid, sub = "did:example:holder", exp = expiration,
            vc = new { credentialSubject = new { marker = ClaimMarker, degree = new { name = "Bachelor" } } }
        });
        var privateKey = _issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            return Ed25519JwtSigner.CreateSignedJwt(header, payload, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public void Dispose()
    {
        _issuerKey.Dispose();
        _limiter.Dispose();
        _dbContext.Dispose();
    }

    private sealed class TenantContext(Guid tenantId) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenantId;
    }
}
