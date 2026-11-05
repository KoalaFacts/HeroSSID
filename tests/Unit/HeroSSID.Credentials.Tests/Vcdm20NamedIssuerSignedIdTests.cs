using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Authenticated named issuer and credential ID must be checked together
/// before a relying party can release signed subject assertions.
/// </summary>
public sealed class Vcdm20NamedIssuerSignedIdTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/001");
    private static readonly Uri OtherCredentialId = new("https://issuer.example/credentials/member/002");
    private const string CredentialType = "MembershipCredential";
    private const string IssuerName = "Koala Facts Example Membership Issuer";
    private readonly byte[] _issuerSeed;
    private readonly byte[] _holderSeed;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public Vcdm20NamedIssuerSignedIdTests()
    {
        (_issuerSeed, byte[] issuerPublic) = NewKey();
        (_holderSeed, byte[] holderPublic) = NewKey();
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void GenuineNamedIssuerAndSignedCredentialIdRequireAllIndependentPins()
    {
        string jwt = Issue(CredentialId);
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));

        Assert.Equal("vc+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("vc", header.RootElement.GetProperty("cty").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, payload.RootElement.GetProperty("id").GetString());
        JsonElement descriptor = payload.RootElement.GetProperty("issuer");
        Assert.Equal(2, descriptor.EnumerateObject().Count());
        Assert.Equal(_issuerDid, descriptor.GetProperty("id").GetString());
        Assert.Equal(IssuerName, descriptor.GetProperty("name").GetString());
        Assert.True(Check(jwt, _issuerDid, IssuerName, _holderDid, CredentialId,
            Now, out JsonElement subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Fact]
    public void OtherGenuinelySignedCredentialAndIssuerNameNeverReleaseClaims()
    {
        string first = Issue(CredentialId);
        string second = Issue(OtherCredentialId);
        Assert.False(Check(second, _issuerDid, IssuerName, _holderDid, CredentialId,
            Now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(first, _issuerDid, "Untrusted Display Name", _holderDid,
            CredentialId, Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.True(Check(second, _issuerDid, IssuerName, _holderDid, OtherCredentialId,
            Now, out JsonElement accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    [Fact]
    public void UntrustedSignerHolderAndOldProfileCannotBypassStrictCombinedPolicy()
    {
        string jwt = Issue(CredentialId);
        Assert.False(Check(jwt, _holderDid, IssuerName, _holderDid, CredentialId,
            Now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(jwt, _issuerDid, IssuerName, _issuerDid, CredentialId,
            Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        // Neither legacy single-field profile silently accepts the combined shape.
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            jwt, _issuerDid, IssuerName, _holderDid, CredentialType,
            Context, Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Vcdm20JoseCredential.TryVerifyWithId(
            jwt, _issuerDid, _holderDid, CredentialType, Context, Now,
            out denied, out string? deniedId));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Null(deniedId);
    }

    [Fact]
    public void TamperingExpiryAndWrongSigningKeyAlwaysFailClosed()
    {
        string jwt = Issue(CredentialId);
        string[] segments = jwt.Split('.');
        char[] signature = segments[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        segments[2] = new string(signature);
        Assert.False(Check(string.Join('.', segments), _issuerDid, IssuerName,
            _holderDid, CredentialId, Now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        Assert.True(Check(jwt, _issuerDid, IssuerName, _holderDid, CredentialId,
            Now.AddMinutes(-1), out _));
        Assert.False(Check(jwt, _issuerDid, IssuerName, _holderDid, CredentialId,
            Now.AddMinutes(10), out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        using var subject = Subject();
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JoseCredential.CreateWithNamedIssuerAndId(
                _issuerDid, IssuerName, _holderDid, CredentialType, Context,
                subject.RootElement, _holderSeed, Now.AddMinutes(-1),
                Now.AddMinutes(10), CredentialId));
    }

    private bool Check(string jwt, string issuerDid, string issuerName, string holderDid,
        Uri id, DateTimeOffset now, out JsonElement subject) =>
        Vcdm20JoseCredential.TryVerifyNamedIssuerWithId(
            jwt, issuerDid, issuerName, holderDid, CredentialType,
            Context, id, now, out subject);

    private string Issue(Uri id)
    {
        using var subject = Subject();
        return Vcdm20JoseCredential.CreateWithNamedIssuerAndId(
            _issuerDid, IssuerName, _holderDid, CredentialType, Context,
            subject.RootElement, _issuerSeed, Now.AddMinutes(-1),
            Now.AddMinutes(10), id);
    }

    private JsonDocument Subject() => JsonDocument.Parse(
        JsonSerializer.Serialize(new { id = _holderDid, membership = "active" }));

    private static (byte[] Seed, byte[] PublicKey) NewKey()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
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
