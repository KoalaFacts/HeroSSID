using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20RequiredSubjectClaimsTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 10, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/context/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member-12");
    private const string CredentialType = "MembershipCredential";
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _replacement = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void SignedActiveMembershipClaimsPassOnlyForIndependentlyTrustedKeys()
    {
        string[] trusted = [_issuer.Did, _replacement.Did];
        foreach (var signer in new[] { _issuer, _replacement })
        {
            string jwt = Issue(signer, "active");
            Assert.True(Check(jwt, trusted, new Dictionary<string, string>
            {
                ["membership"] = "active", ["tier"] = "standard"
            }, out string actualIssuer, out JsonElement subject));
            Assert.Equal(signer.Did, actualIssuer);
            Assert.Equal("active", subject.GetProperty("membership").GetString());
            Assert.Equal(_holder.Did, subject.GetProperty("id").GetString());
        }
    }

    [Fact]
    public void GenuinelySignedInactiveMembershipCannotSatisfyActivePolicy()
    {
        string jwt = Issue(_issuer, "inactive");
        Assert.False(Check(jwt, [_issuer.Did],
            new Dictionary<string, string> { ["membership"] = "active" },
            out string signer, out JsonElement subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    [Fact]
    public void MissingNestedAndUnsupportedClaimPoliciesNeverReleaseSubject()
    {
        string jwt = Issue(_issuer, "active");
        IReadOnlyDictionary<string, string>[] policies =
        [
            new Dictionary<string, string> { ["missing"] = "yes" },
            new Dictionary<string, string> { ["tier"] = "gold" },
            new Dictionary<string, string> { ["id"] = _holder.Did },
            new Dictionary<string, string>(),
            new Dictionary<string, string> { [" membership"] = "active" },
            new Dictionary<string, string> { ["membership"] = "" },
            Enumerable.Range(0, 17).ToDictionary(i => "claim" + i, _ => "value")
        ];
        foreach (var policy in policies)
        {
            Assert.False(Check(jwt, [_issuer.Did], policy, out string signer, out JsonElement claims));
            Assert.Equal(string.Empty, signer);
            Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        }
    }

    [Fact]
    public void WrongIssuerOrCredentialIdOrTamperedTokenCannotSatisfyValidClaimPolicy()
    {
        string original = Issue(_issuer, "active");
        var required = new Dictionary<string, string> { ["membership"] = "active" };
        string[] chunks = original.Split('.');
        chunks[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(original)
            .Replace("\"active\"", "\"inactive\"", StringComparison.Ordinal));
        string tampered = string.Join('.', chunks);
        Assert.False(Check(original, [_replacement.Did], required, out _, out _));
        Assert.False(Check(tampered, [_issuer.Did], required, out _, out _));
        Assert.False(Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
            original, [_issuer.Did], _holder.Did, CredentialType,
            Vocabulary, new Uri("https://issuer.example/credentials/other"),
            required, Now, out string signer, out JsonElement claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private bool Check(string jwt, IReadOnlyCollection<string> trusted,
        IReadOnlyDictionary<string, string> required,
        out string issuerDid, out JsonElement subject) =>
        Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
            jwt, trusted, _holder.Did, CredentialType, Vocabulary,
            CredentialId, required, Now, out issuerDid, out subject);

    private string Issue((byte[] Seed, string Did) issuer, string status)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _holder.Did, membership = status, tier = "standard",
            metadata = new { tier = "gold" }
        }));
        return Vcdm20JoseCredential.CreateWithId(
            issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(10), CredentialId);
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        publicKey.CopyTo(encoded, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded));
    }
}
