using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20JoseCredentialTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private const string ContextUri = "https://example.org/credentials/membership/v1";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new(ContextUri);
    private static readonly string[] LegacyContexts = ["https://www.w3.org/2018/credentials/v1"];
    private static readonly string[] LegacyTypes = ["VerifiableCredential", CredentialType];
    private readonly byte[] _issuerSeed;
    private readonly byte[] _holderSeed;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public Vcdm20JoseCredentialTests()
    {
        (_issuerSeed, var issuerPublic) = NewKey();
        (_holderSeed, var holderPublic) = NewKey();
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void IndependentIssuerCanCreateAndVerifierCanReadRealSignedVcdm20Subject()
    {
        string signed = Issue();
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(signed));
        var root = document.RootElement;
        Assert.Equal("https://www.w3.org/ns/credentials/v2", root.GetProperty("@context")[0].GetString());
        Assert.Equal(ContextUri, root.GetProperty("@context")[1].GetString());
        Assert.False(root.TryGetProperty("vc", out _));
        Assert.Equal(_issuerDid, root.GetProperty("issuer").GetString());
        Assert.Equal(_holderDid, root.GetProperty("credentialSubject").GetProperty("id").GetString());
        Assert.True(Vcdm20JoseCredential.TryVerify(
            signed, _issuerDid, _holderDid, CredentialType, Context, Now, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Fact]
    public void AttackerKeyCannotIssueForAnUncontrolledIssuerDid()
    {
        using var subject = Subject();
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.Create(
            _issuerDid, _holderDid, CredentialType, Context,
            subject.RootElement, _holderSeed, Now.AddMinutes(-1), Now.AddMinutes(10)));
    }

    [Fact]
    public void ReSignedWrongContextOrHolderFailsPinnedPolicyEvenWithRealIssuerKey()
    {
        string valid = Issue();
        string header = Ed25519JwtSigner.ExtractHeader(valid);
        string payload = Ed25519JwtSigner.ExtractPayload(valid);
        string foreignContext = Ed25519JwtSigner.CreateSignedJwt(header,
            payload.Replace(ContextUri, "https://attacker.example/schema",
                StringComparison.Ordinal), _issuerSeed);
        Assert.False(Vcdm20JoseCredential.TryVerify(foreignContext,
            _issuerDid, _holderDid, CredentialType, Context, Now, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Vcdm20JoseCredential.TryVerify(valid,
            _issuerDid, _issuerDid, CredentialType, Context, Now, out _));
        Assert.False(Vcdm20JoseCredential.TryVerify(valid,
            _holderDid, _holderDid, CredentialType, Context, Now, out _));
    }

    [Fact]
    public void TamperedOrExpiredTokenAndLegacyNestedVcNeverExposeClaims()
    {
        string valid = Issue();
        var parts = valid.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(valid).Replace("active", "admin", StringComparison.Ordinal));
        Assert.False(Vcdm20JoseCredential.TryVerify(string.Join('.', parts),
            _issuerDid, _holderDid, CredentialType, Context, Now, out _));
        Assert.False(Vcdm20JoseCredential.TryVerify(valid,
            _issuerDid, _holderDid, CredentialType, Context, Now.AddHours(1), out _));
        string legacy = Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = _issuerDid, sub = _holderDid, iat = Now.ToUnixTimeSeconds(),
                vc = new { context = LegacyContexts,
                    type = LegacyTypes,
                    credentialSubject = new { id = _holderDid, membership = "active" } }
            }), _issuerSeed);
        Assert.False(Vcdm20JoseCredential.TryVerify(legacy,
            _issuerDid, _holderDid, CredentialType, Context, Now, out _));
    }

    private string Issue()
    {
        using var subject = Subject();
        return Vcdm20JoseCredential.Create(
            _issuerDid, _holderDid, CredentialType, Context,
            subject.RootElement, _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private JsonDocument Subject() => JsonDocument.Parse(
        JsonSerializer.Serialize(new { id = _holderDid, membership = "active" }));

    private static (byte[] Seed, byte[] PublicKey) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    private static string DidFromKey(byte[] publicKey)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        publicKey.CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
