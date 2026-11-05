using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Independently pinned recipient restrictions on genuinely issued VC2 JWTs.
/// An issuer's recipient assertion never proves holder control or business authority.
/// </summary>
public sealed class Vcdm20AudienceBoundCredentialTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 1, 0, 0, TimeSpan.Zero);
    private static readonly Uri Context = new("https://issuer.example/context/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/one");
    private static readonly Uri OtherCredentialId = new("https://issuer.example/credentials/member/two");
    private static readonly Uri Recipient = new("https://verifier.example/checks/membership");
    private static readonly Uri OtherRecipient = new("https://other-verifier.example/checks/membership");
    private const string CredentialType = "MembershipCredential";

    private readonly byte[] _issuerSeed;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public Vcdm20AudienceBoundCredentialTests()
    {
        (_issuerSeed, byte[] issuerPublic) = NewKey();
        (_, byte[] holderPublic) = NewKey();
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void GenuineSignedVc2HasExactOriginalRecipientAndCredentialId()
    {
        string jwt = Issue(Recipient);
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal("vc+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("vc", header.RootElement.GetProperty("cty").GetString());
        Assert.Equal(8, payload.RootElement.EnumerateObject().Count());
        Assert.Equal(Recipient.AbsoluteUri, payload.RootElement.GetProperty("aud").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, payload.RootElement.GetProperty("id").GetString());
        Assert.True(Check(jwt, _issuerDid, _holderDid, CredentialId, Recipient,
            Now, out JsonElement subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Fact]
    public void ValidIssuerSignedCredentialForAnotherRecipientNeverReleasesClaims()
    {
        string first = Issue(Recipient);
        string second = Issue(OtherRecipient);
        Assert.False(Check(first, _issuerDid, _holderDid, CredentialId, OtherRecipient,
            Now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(second, _issuerDid, _holderDid, CredentialId, Recipient,
            Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.True(Check(second, _issuerDid, _holderDid, CredentialId, OtherRecipient,
            Now, out JsonElement accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());

        Assert.False(Vcdm20JoseCredential.TryVerifyWithId(first, _issuerDid, _holderDid,
            CredentialType, Context, Now, out denied, out string? deniedId));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Null(deniedId);
    }

    [Fact]
    public void IndependentIssuerHolderAndCredentialIdPolicyCannotBeReplacedBySignedAudience()
    {
        string jwt = Issue(Recipient);
        Assert.False(Check(jwt, _holderDid, _holderDid, CredentialId, Recipient,
            Now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(jwt, _issuerDid, _issuerDid, CredentialId, Recipient,
            Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(jwt, _issuerDid, _holderDid, OtherCredentialId, Recipient,
            Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        string[] parts = jwt.Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(signature);
        Assert.False(Check(string.Join('.', parts), _issuerDid, _holderDid,
            CredentialId, Recipient, Now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void ExpiryAndUnsafeRecipientUrlsFailClosed()
    {
        string jwt = Issue(Recipient);
        Assert.False(Check(jwt, _issuerDid, _holderDid, CredentialId,
            Recipient, Now.AddMinutes(11), out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        using var subject = Subject();
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuerDid, _holderDid, CredentialType, Context, subject.RootElement,
            _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10),
            CredentialId, new Uri("http://verifier.example/insecure")));
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuerDid, _holderDid, CredentialType, Context, subject.RootElement,
            _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10),
            CredentialId, new Uri("https://user:secret@verifier.example/check")));
        Assert.False(Check(jwt, _issuerDid, _holderDid, CredentialId,
            new Uri("https://verifier.example/checks/membership#fragment"), Now,
            out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    private static bool Check(string jwt, string issuer, string holder, Uri id, Uri audience,
        DateTimeOffset now, out JsonElement verified) =>
        Vcdm20JoseCredential.TryVerifyForAudienceWithId(
            jwt, issuer, holder, CredentialType, Context, id, audience, now,
            out verified);

    private string Issue(Uri audience)
    {
        using var subject = Subject();
        return Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuerDid, _holderDid, CredentialType, Context,
            subject.RootElement, _issuerSeed, Now.AddMinutes(-1), Now.AddMinutes(10),
            CredentialId, audience);
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
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
