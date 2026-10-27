using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// An enrolled issuer's genuine signature does not by itself make arbitrary JWT JSON a credential.
/// </summary>
public sealed class CredentialMinimumStructureTests : IDisposable
{
    private const string IssuerDid = "did:example:minimum-issuer";
    private const string HolderDid = "did:example:minimum-holder";
    private const string Header = "{\"typ\":\"vc+jwt\",\"alg\":\"EdDSA\"}";
    private static readonly string[] CredentialTypes = ["VerifiableCredential", "RoleCredential"];
    private static readonly string[] NoBaseType = ["RoleCredential"];
    private static readonly string[] BlankSpecificType = ["VerifiableCredential", " "];
    private static readonly Guid IssuerTenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid RequesterTenant = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private readonly HeroDbContext _db = new(new DbContextOptionsBuilder<HeroDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
    private readonly InMemoryRateLimiter _limiter = new(TimeSpan.FromMinutes(1), 100);
    private readonly Key _issuerKey = Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    [Theory]
    [InlineData("issuer-only")]
    [InlineData("missing-sub")]
    [InlineData("null-sub")]
    [InlineData("nonstring-sub")]
    [InlineData("missing-iat")]
    [InlineData("string-iat")]
    [InlineData("future-iat")]
    [InlineData("missing-vc")]
    [InlineData("nonobject-vc")]
    [InlineData("missing-type")]
    [InlineData("scalar-type")]
    [InlineData("missing-base-type")]
    [InlineData("blank-specialised-type")]
    [InlineData("missing-credential-subject")]
    [InlineData("nonobject-credential-subject")]
    [InlineData("subject-id-mismatch")]
    [InlineData("future-nbf")]
    [InlineData("string-nbf")]
    public async Task GenuineIssuerSignatureCannotMakeInvalidStructureAVerifiedCredential(string defect)
    {
        await EnrollIssuerAsync().ConfigureAwait(true);
        var payload = CompletePayload();
        MakeInvalid(payload, defect);
        var jwt = Sign(payload.ToJsonString());
        var verifier = new CredentialVerificationService(_db, _limiter);

        var local = await verifier.VerifyCredentialAsync(new TenantContext(IssuerTenant), jwt).ConfigureAwait(true);
        var crossTenant = await verifier.VerifyCredentialFromIssuerAsync(
            new TenantContext(RequesterTenant), IssuerTenant, jwt).ConfigureAwait(true);

        AssertMalformedAndUndisclosed(local);
        AssertMalformedAndUndisclosed(crossTenant);
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("null")]
    [InlineData("future")]
    public async Task CompleteIssuerSignedCredentialRemainsValidAcrossBothEntryPoints(string expiration)
    {
        await EnrollIssuerAsync().ConfigureAwait(true);
        var payload = CompletePayload();
        payload["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds();
        if (expiration == "null")
        {
            payload["exp"] = null;
        }
        else if (expiration == "future")
        {
            payload["exp"] = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds();
        }

        var jwt = Sign(payload.ToJsonString());
        var verifier = new CredentialVerificationService(_db, _limiter);
        var local = await verifier.VerifyCredentialAsync(new TenantContext(IssuerTenant), jwt).ConfigureAwait(true);
        var crossTenant = await verifier.VerifyCredentialFromIssuerAsync(
            new TenantContext(RequesterTenant), IssuerTenant, jwt).ConfigureAwait(true);

        foreach (var result in new[] { local, crossTenant })
        {
            Assert.True(result.IsValid);
            Assert.Equal(VerificationStatus.Valid, result.Status);
            Assert.Empty(result.ValidationErrors);
            Assert.Equal(IssuerDid, result.IssuerDid);
            Assert.NotNull(result.CredentialSubject);
            Assert.Equal(HolderDid, Assert.IsType<JsonElement>(result.CredentialSubject["id"]).GetString());
            Assert.Equal("Member", Assert.IsType<JsonElement>(result.CredentialSubject["role"]).GetString());
            Assert.Equal(expiration == "future", result.ExpiresAt.HasValue);
        }
    }

    [Theory]
    [InlineData("VerifiableCredential")]
    [InlineData("MembershipCredential")]
    public async Task IssuerOutputRoundTripsForEveryPreviouslyAcceptedType(string credentialType)
    {
        await EnrollIssuerAsync().ConfigureAwait(true);
        var issuer = await _db.Dids.SingleAsync(d => d.DidIdentifier == IssuerDid).ConfigureAwait(true);

        using var holderKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var holderPublicKey = holderKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var holder = new DidEntity
        {
            Id = Guid.NewGuid(), TenantId = RequesterTenant, DidIdentifier = HolderDid,
            PublicKeyEd25519 = holderPublicKey, KeyFingerprint = SHA256.HashData(holderPublicKey),
            PrivateKeyEd25519Encrypted = new byte[64], DidDocumentJson = "{}",
            Status = "active", CreatedAt = DateTimeOffset.UtcNow
        };
        _db.Dids.Add(holder);
        await _db.SaveChangesAsync().ConfigureAwait(true);

        // This uses the actual issuer and verifier with a real enrolled signing key.
        // It does not establish independent wallet interop or holder-key control.
        var issuerService = new CredentialIssuanceService(_db, new TestIssuerKeyEncryption(_issuerKey), _limiter);
        var jwt = await issuerService.IssueCredentialAsync(
            new TenantContext(IssuerTenant), issuer.Id, holder.Id, credentialType,
            new Dictionary<string, object> { ["role"] = "member" }).ConfigureAwait(true);
        var verified = await new CredentialVerificationService(_db, _limiter)
            .VerifyCredentialAsync(new TenantContext(IssuerTenant), jwt).ConfigureAwait(true);

        Assert.True(verified.IsValid, string.Join("; ", verified.ValidationErrors));
        Assert.Equal(VerificationStatus.Valid, verified.Status);
        Assert.Equal(IssuerDid, verified.IssuerDid);
        Assert.NotNull(verified.CredentialSubject);
        Assert.Equal("member", Assert.IsType<JsonElement>(verified.CredentialSubject["role"]).GetString());
    }

    private static JsonObject CompletePayload() => JsonNode.Parse(JsonSerializer.Serialize(new
    {
        iss = IssuerDid,
        sub = HolderDid,
        iat = DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds(),
        vc = new
        {
            type = CredentialTypes,
            credentialSubject = new { id = HolderDid, role = "Member" }
        }
    }))!.AsObject();

    private static void MakeInvalid(JsonObject payload, string defect)
    {
        switch (defect)
        {
            case "issuer-only":
                payload.Clear();
                payload["iss"] = IssuerDid;
                break;
            case "missing-sub": payload.Remove("sub"); break;
            case "null-sub": payload["sub"] = null; break;
            case "nonstring-sub": payload["sub"] = 42; break;
            case "missing-iat": payload.Remove("iat"); break;
            case "string-iat": payload["iat"] = "1000"; break;
            case "future-iat": payload["iat"] = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(); break;
            case "missing-vc": payload.Remove("vc"); break;
            case "nonobject-vc": payload["vc"] = "not-a-credential"; break;
            case "missing-type": payload["vc"]!.AsObject().Remove("type"); break;
            case "scalar-type": payload["vc"]!["type"] = "VerifiableCredential"; break;
            case "missing-base-type":
                payload["vc"]!["type"] = JsonSerializer.SerializeToNode(NoBaseType);
                break;
            case "blank-specialised-type":
                payload["vc"]!["type"] = JsonSerializer.SerializeToNode(BlankSpecificType);
                break;
            case "missing-credential-subject": payload["vc"]!.AsObject().Remove("credentialSubject"); break;
            case "nonobject-credential-subject": payload["vc"]!["credentialSubject"] = "not-an-object"; break;
            case "subject-id-mismatch": payload["vc"]!["credentialSubject"]!["id"] = "did:example:another-holder"; break;
            case "future-nbf": payload["nbf"] = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(); break;
            case "string-nbf": payload["nbf"] = "0"; break;
            default: throw new ArgumentOutOfRangeException(nameof(defect));
        }
    }

    private async Task EnrollIssuerAsync()
    {
        var publicKey = _issuerKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        _db.Dids.Add(new DidEntity
        {
            Id = Guid.NewGuid(), TenantId = IssuerTenant, DidIdentifier = IssuerDid,
            PublicKeyEd25519 = publicKey, KeyFingerprint = SHA256.HashData(publicKey),
            PrivateKeyEd25519Encrypted = new byte[64], DidDocumentJson = "{}",
            Status = "active", CreatedAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync().ConfigureAwait(true);
    }

    private string Sign(string payload)
    {
        var privateKey = _issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            return Ed25519JwtSigner.CreateSignedJwt(Header, payload, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private static void AssertMalformedAndUndisclosed(CredentialVerificationResult result)
    {
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.MalformedJwt, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
        Assert.Null(result.IssuerDid);
        Assert.Null(result.CredentialSubject);
        Assert.Null(result.ExpiresAt);
    }

    public void Dispose()
    {
        _issuerKey.Dispose();
        _limiter.Dispose();
        _db.Dispose();
    }

    private sealed class TestIssuerKeyEncryption(Key issuerKey) : IKeyEncryptionService
    {
        public byte[] Decrypt(byte[] ciphertext) => issuerKey.Export(KeyBlobFormat.RawPrivateKey);
        public byte[] Encrypt(byte[] plaintext) => throw new NotSupportedException();
        public string EncryptString(string plaintext) => throw new NotSupportedException();
        public string DecryptString(string ciphertext) => throw new NotSupportedException();
    }

    private sealed class TenantContext(Guid id) : ITenantContext
    {
        public Guid GetCurrentTenantId() => id;
    }
}
