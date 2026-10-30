using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonCredentialTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 6, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();

    [Fact]
    public void IssuerCreatesGenuineJwtVcJsonWithStandardContextAndIndependentVerification()
    {
        string jwt = Issue();
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        var payload = document.RootElement;
        Assert.Equal("vc+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(_issuer.Did + "#" + _issuer.Did["did:key:".Length..],
            header.RootElement.GetProperty("kid").GetString());
        Assert.Equal(_issuer.Did, payload.GetProperty("iss").GetString());
        Assert.Equal(_holder.Did, payload.GetProperty("sub").GetString());
        var vc = payload.GetProperty("vc");
        Assert.False(vc.TryGetProperty("context", out _));
        Assert.Equal("https://www.w3.org/2018/credentials/v1",
            vc.GetProperty("@context")[0].GetString());
        Assert.Equal(Vocabulary.AbsoluteUri, vc.GetProperty("@context")[1].GetString());
        Assert.Equal(CredentialType, vc.GetProperty("type")[1].GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
    }

    [Fact]
    public void WrongIssuerHolderVocabularyOrTypeNeverReleasesClaims()
    {
        string jwt = Issue();
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var otherIssuer));
        Assert.Equal(JsonValueKind.Undefined, otherIssuer.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            "AdminCredential", Vocabulary, Now, out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, new Uri("https://other.example/v1"), Now, out _));
    }

    [Fact]
    public void TamperingOldPrivateContextAndDirectVc2AreRejected()
    {
        string jwt = Issue();
        var parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(jwt)
            .Replace("active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts), _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));

        string oldProfile = SignPayload(new
        {
            iss = _issuer.Did, sub = _holder.Did,
            iat = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            nbf = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            exp = Now.AddMinutes(10).ToUnixTimeSeconds(),
            vc = new
            {
                context = new[] { "https://www.w3.org/2018/credentials/v1", Vocabulary.AbsoluteUri },
                type = new[] { "VerifiableCredential", CredentialType },
                credentialSubject = new { id = _holder.Did, membership = "active" }
            }
        });
        Assert.False(JwtVcJsonCredential.TryVerify(oldProfile, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string direct = Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, CredentialType,
            Vocabulary, subject.RootElement, _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
        Assert.False(JwtVcJsonCredential.TryVerify(direct, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void ExpiredAndPrematureCredentialsFailClosed()
    {
        string jwt = Issue();
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMinutes(11), out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMinutes(-2), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void MismatchedIssuerPrivateKeyAndSubjectAreRejectedAtIssuance()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, subject.RootElement,
            _other.Seed, Now.AddMinutes(-1), Now.AddMinutes(10)));
        using var alienSubject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _other.Did, membership = "active" }));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, alienSubject.RootElement,
            _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10)));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, subject.RootElement,
            _issuer.Seed, Now, Now.AddHours(1)));
    }

    private string Issue()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private string SignPayload<T>(T payload)
    {
        string kid = _issuer.Did + "#" + _issuer.Did["did:key:".Length..];
        return Ed25519JwtSigner.CreateSignedJwt(JsonSerializer.Serialize(
            new { alg = "EdDSA", typ = "vc+jwt", kid }),
            JsonSerializer.Serialize(payload), _issuer.Seed);
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
