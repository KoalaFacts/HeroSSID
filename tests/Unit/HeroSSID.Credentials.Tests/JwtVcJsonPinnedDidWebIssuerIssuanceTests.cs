using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real Ed25519 issuer signing under an externally enrolled did:web assertion
/// method. The verifier, not the credential or Wallet, owns the trust pin.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebIssuerIssuanceTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string AssertionMethod = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");
    private static readonly DateTimeOffset Now = new(2026, 11, 7, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DidWebIssuerSignsAStandardVc11JwtVerifiedAgainstIndependentIssuerPin()
    {
        var issuer = Identity();
        var holder = Identity();
        string jwt = Issue(issuer.Seed, issuer.PublicKey, holder.Did);

        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("EdDSA", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal(AssertionMethod, header.RootElement.GetProperty("kid").GetString());
        Assert.Equal(IssuerDid, payload.RootElement.GetProperty("iss").GetString());
        Assert.Equal(holder.Did, payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, payload.RootElement.GetProperty("jti").GetString());

        JsonElement vc = payload.RootElement.GetProperty("vc");
        Assert.Equal("https://www.w3.org/2018/credentials/v1",
            vc.GetProperty("@context")[0].GetString());
        Assert.Equal(Context.AbsoluteUri, vc.GetProperty("@context")[1].GetString());
        Assert.Equal(CredentialType, vc.GetProperty("type")[1].GetString());
        Assert.Equal(IssuerDid, vc.GetProperty("issuer").GetProperty("id").GetString());
        Assert.Equal(IssuerName, vc.GetProperty("issuer").GetProperty("name").GetString());

        Assert.True(Verify(jwt, issuer.PublicKey, holder.Did, IssuerName,
            CredentialId, out JsonElement verified));
        Assert.Equal("member", verified.GetProperty("role").GetString());
    }

    [Fact]
    public void WrongSignerOrMismatchedPinnedIssuerMetadataNeverBecomesAValidCredential()
    {
        var issuer = Identity();
        var attacker = Identity();
        var holder = Identity();

        Assert.Throws<ArgumentException>(() =>
            Issue(attacker.Seed, issuer.PublicKey, holder.Did));
        Assert.Throws<ArgumentException>(() =>
            Issue(issuer.Seed, attacker.PublicKey, holder.Did));

        string valid = Issue(issuer.Seed, issuer.PublicKey, holder.Did);
        Assert.False(Verify(valid, attacker.PublicKey, holder.Did, IssuerName,
            CredentialId, out JsonElement wrongKey));
        Assert.Equal(JsonValueKind.Undefined, wrongKey.ValueKind);
        Assert.False(Verify(valid, issuer.PublicKey, holder.Did, "Unknown Organisation",
            CredentialId, out JsonElement wrongName));
        Assert.Equal(JsonValueKind.Undefined, wrongName.ValueKind);
        Assert.False(Verify(valid, issuer.PublicKey, holder.Did, IssuerName,
            new Uri("https://issuer.example/credentials/other"), out JsonElement wrongId));
        Assert.Equal(JsonValueKind.Undefined, wrongId.ValueKind);

        string[] parts = valid.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(valid)
            .Replace("member", "administrator", StringComparison.Ordinal));
        Assert.False(Verify(string.Join('.', parts), issuer.PublicKey, holder.Did,
            IssuerName, CredentialId, out JsonElement forged));
        Assert.Equal(JsonValueKind.Undefined, forged.ValueKind);
    }

    [Fact]
    public void IssuanceRejectsWrongDidMethodSubjectAndInvalidSigningInputs()
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = Subject(holder.Did);
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
                "did:web:localhost", AssertionMethod, issuer.PublicKey,
                holder.Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                IssuerName, CredentialId));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
                IssuerDid, IssuerDid + "#untrusted", issuer.PublicKey,
                holder.Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                IssuerName, CredentialId));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
                IssuerDid, AssertionMethod, issuer.PublicKey,
                Identity().Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                IssuerName, CredentialId));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
                IssuerDid, AssertionMethod, new byte[32],
                holder.Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                IssuerName, CredentialId));
    }

    [Fact]
    public void LegacyDidKeyIssuerCannotSilentlyEmitDidWebJwts()
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = Subject(holder.Did);
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonCredential.Create(IssuerDid, holder.Did, CredentialType,
                Context, subject.RootElement, issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(5), CredentialId));
    }

    private static string Issue(byte[] seed, byte[] signingPublicKey, string holderDid)
    {
        using var subject = Subject(holderDid);
        return JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, AssertionMethod, signingPublicKey, holderDid,
            CredentialType, Context, subject.RootElement, seed,
            Now.AddMinutes(-1), Now.AddMinutes(5), IssuerName, CredentialId);
    }

    private static bool Verify(string jwt, byte[] publicKey, string holderDid,
        string issuerName, Uri credentialId, out JsonElement verified) =>
        JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
            jwt, IssuerDid, AssertionMethod, publicKey, issuerName, credentialId,
            holderDid, CredentialType, Context, Now, out verified);

    private static JsonDocument Subject(string holderDid) =>
        JsonDocument.Parse(JsonSerializer.Serialize(new { id = holderDid, role = "member" }));

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
