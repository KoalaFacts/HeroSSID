using System.Globalization;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Direct VC2 JOSE from an independently pinned organisation did:web key:
/// real Ed25519 signature, strict assertion kid and exact issuer metadata.
/// </summary>
public sealed class Vcdm20PinnedDidWebIssuerTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/1234");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public void GenuineDirectVc2IssuerSignatureAndAllIndependentPinsAreAccepted(string keySuffix)
    {
        var issued = Issue(keySuffix);
        Assert.True(Check(issued.Jwt, IssuerDid, issued.MethodId,
            issued.IssuerPublicKey, IssuerName, CredentialId, issued.HolderDid,
            Type, Context, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Fact]
    public void ValidSignatureWithWrongMethodKeyOrSignedMetadataCannotReleaseSubject()
    {
        var issued = Issue("#key-1");
        var other = NewIdentity();
        var cases = new (string Issuer, string Method, byte[] Key, string Name,
            Uri Id, string Holder, string CredentialType, Uri Vocabulary)[]
        {
            ("did:web:other.example", issued.MethodId, issued.IssuerPublicKey,
                IssuerName, CredentialId, issued.HolderDid, Type, Context),
            (IssuerDid, IssuerDid + "#key-2", issued.IssuerPublicKey,
                IssuerName, CredentialId, issued.HolderDid, Type, Context),
            (IssuerDid, issued.MethodId, other.PublicKey,
                IssuerName, CredentialId, issued.HolderDid, Type, Context),
            (IssuerDid, issued.MethodId, issued.IssuerPublicKey,
                "Other issuer", CredentialId, issued.HolderDid, Type, Context),
            (IssuerDid, issued.MethodId, issued.IssuerPublicKey,
                IssuerName, new Uri("https://issuer.example/credentials/other"),
                issued.HolderDid, Type, Context),
            (IssuerDid, issued.MethodId, issued.IssuerPublicKey,
                IssuerName, CredentialId, other.Did, Type, Context),
            (IssuerDid, issued.MethodId, issued.IssuerPublicKey,
                IssuerName, CredentialId, issued.HolderDid, "OtherCredential", Context),
            (IssuerDid, issued.MethodId, issued.IssuerPublicKey,
                IssuerName, CredentialId, issued.HolderDid, Type,
                new Uri("https://other.example/vocab/membership/v1"))
        };
        foreach (var item in cases)
        {
            Assert.False(Check(issued.Jwt, item.Issuer, item.Method,
                item.Key, item.Name, item.Id, item.Holder,
                item.CredentialType, item.Vocabulary, out var subject));
            Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        }
    }

    [Fact]
    public void TamperedExpiredAndUnapprovedKeysFailWithoutClaimDisclosure()
    {
        var issued = Issue("#key-1");
        string[] sections = issued.Jwt.Split('.');
        char[] signature = sections[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        sections[2] = new string(signature);
        Assert.False(Check(string.Join('.', sections),
            IssuerDid, issued.MethodId, issued.IssuerPublicKey,
            IssuerName, CredentialId, issued.HolderDid, Type, Context,
            out var tamperedSubject));
        Assert.Equal(JsonValueKind.Undefined, tamperedSubject.ValueKind);
        Assert.False(Check(issued.Jwt, IssuerDid, issued.MethodId,
            new byte[32], IssuerName, CredentialId, issued.HolderDid,
            Type, Context, out var zeroKeySubject));
        Assert.Equal(JsonValueKind.Undefined, zeroKeySubject.ValueKind);
        Assert.False(Check(issued.Jwt, IssuerDid, issued.MethodId,
            new byte[31], IssuerName, CredentialId, issued.HolderDid,
            Type, Context, out var wrongLengthSubject));
        Assert.Equal(JsonValueKind.Undefined, wrongLengthSubject.ValueKind);
        Assert.False(Check(issued.Jwt, IssuerDid, issued.MethodId,
            issued.IssuerPublicKey, IssuerName, CredentialId, issued.HolderDid,
            Type, Context, out var expiredSubject, now: DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(JsonValueKind.Undefined, expiredSubject.ValueKind);
    }

    private static bool Check(
        string jwt, string trustedIssuer, string trustedMethod, byte[] pinnedKey,
        string trustedName, Uri pinnedId, string holder, string type, Uri vocabulary,
        out JsonElement subject, DateTimeOffset? now = null)
    {
        return Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerNameAndId(
            jwt, trustedIssuer, trustedMethod, pinnedKey, trustedName, pinnedId,
            holder, type, vocabulary, now ?? DateTimeOffset.UtcNow, out subject);
    }

    private static (string Jwt, string HolderDid, byte[] IssuerPublicKey, string MethodId) Issue(
        string suffix)
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        string method = IssuerDid + suffix;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        static string Stamp(DateTimeOffset time) =>
            time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2", Context.AbsoluteUri },
            ["type"] = new[] { "VerifiableCredential", Type },
            ["issuer"] = new { id = IssuerDid, name = IssuerName },
            ["validFrom"] = Stamp(now.AddMinutes(-1)),
            ["validUntil"] = Stamp(now.AddMinutes(10)),
            ["credentialSubject"] = new { id = holder.Did, membership = "active" },
            ["id"] = CredentialId.AbsoluteUri
        };
        string jwt = Ed25519JwtSigner.CreateSignedJwt(
            JsonSerializer.Serialize(new { alg = "EdDSA", typ = "vc+jwt",
                cty = "vc", kid = method }), JsonSerializer.Serialize(claims), issuer.Seed);
        return (jwt, holder.Did, issuer.PublicKey, method);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) NewIdentity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
