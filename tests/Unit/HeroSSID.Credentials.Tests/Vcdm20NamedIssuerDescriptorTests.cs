using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Opt-in issuer-object payload accepted by VCDM 2.0 §4.7. The signer and
/// descriptive name are independently pinned by the relying verifier.
/// This is NOT external JSON-LD or Wallet conformance certification.
/// </summary>
public sealed class Vcdm20NamedIssuerDescriptorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly Uri Context = new("https://example.org/credentials/member/v1");
    private const string Type = "MembershipCredential";
    private const string Name = "Koala Facts Example Issuer";
    private readonly byte[] _issuerSeed;
    private readonly byte[] _holderSeed;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public Vcdm20NamedIssuerDescriptorTests()
    {
        (_issuerSeed, byte[] issuerPublic) = NewKey();
        (_holderSeed, byte[] holderPublic) = NewKey();
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void SignedNamedIssuerObjectCanBeVerifiedAgainstIndependentIdAndNamePins()
    {
        string signed = IssueNamed();
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(signed));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(signed));

        Assert.Equal("vc+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("vc", header.RootElement.GetProperty("cty").GetString());
        var issuer = payload.RootElement.GetProperty("issuer");
        Assert.Equal(JsonValueKind.Object, issuer.ValueKind);
        Assert.Equal(2, issuer.EnumerateObject().Count());
        Assert.Equal(_issuerDid, issuer.GetProperty("id").GetString());
        Assert.Equal(Name, issuer.GetProperty("name").GetString());
        Assert.True(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            signed, _issuerDid, Name, _holderDid, Type, Context, Now,
            out var verifiedSubject));
        Assert.Equal("active", verifiedSubject.GetProperty("membership").GetString());
    }

    [Fact]
    public void ValidlySignedWrongNameOrUnpinnedIssuerNeverReleasesSubject()
    {
        string signed = IssueNamed();
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            signed, _issuerDid, "Different Example Issuer", _holderDid, Type,
            Context, Now, out var refusedSubject));
        Assert.Equal(JsonValueKind.Undefined, refusedSubject.ValueKind);
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            signed, _holderDid, Name, _holderDid, Type,
            Context, Now, out refusedSubject));
        Assert.Equal(JsonValueKind.Undefined, refusedSubject.ValueKind);

        // The existing string-only public verifier must not silently accept
        // a new issuer representation without the caller opting in.
        Assert.False(Vcdm20JoseCredential.TryVerify(
            signed, _issuerDid, _holderDid, Type, Context, Now, out refusedSubject));
        Assert.Equal(JsonValueKind.Undefined, refusedSubject.ValueKind);
    }

    [Fact]
    public void ForeignFieldsAndTamperedClaimAreRejectedEvenWhenIssuerResigns()
    {
        string signed = IssueNamed();
        string header = Ed25519JwtSigner.ExtractHeader(signed);
        string payload = Ed25519JwtSigner.ExtractPayload(signed);
        string extra = payload.Replace(
            "\"name\":\"" + Name + "\"",
            "\"name\":\"" + Name + "\",\"alsoKnownAs\":\"https://attacker.example\"",
            StringComparison.Ordinal);
        Assert.NotEqual(payload, extra);
        string signedWithUnknownIssuerPolicy = Ed25519JwtSigner.CreateSignedJwt(
            header, extra, _issuerSeed);
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            signedWithUnknownIssuerPolicy, _issuerDid, Name, _holderDid, Type,
            Context, Now, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        var pieces = signed.Split('.');
        pieces[1] = Base64UrlEncoder.Encode(payload.Replace(
            "\"membership\":\"active\"", "\"membership\":\"admin\"",
            StringComparison.Ordinal));
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            string.Join('.', pieces), _issuerDid, Name, _holderDid, Type,
            Context, Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void OldStringIssuerAndUncontrolledSignerKeyCannotImpersonateNamedIssuer()
    {
        using var subject = Subject();
        string old = Vcdm20JoseCredential.Create(
            _issuerDid, _holderDid, Type, Context, subject.RootElement,
            _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
        Assert.False(Vcdm20JoseCredential.TryVerifyNamedIssuer(
            old, _issuerDid, Name, _holderDid, Type, Context, Now, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.CreateWithNamedIssuer(
            _issuerDid, Name, _holderDid, Type, Context, subject.RootElement,
            _holderSeed, Now.AddMinutes(-1), Now.AddMinutes(10)));
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.CreateWithNamedIssuer(
            _issuerDid, " ", _holderDid, Type, Context, subject.RootElement,
            _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10)));
    }

    private string IssueNamed()
    {
        using var subject = Subject();
        return Vcdm20JoseCredential.CreateWithNamedIssuer(
            _issuerDid, Name, _holderDid, Type, Context, subject.RootElement,
            _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10));
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
