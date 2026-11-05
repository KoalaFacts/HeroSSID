using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20JoseCredentialIdTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 6, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/context/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/serial-12");
    private const string CredentialType = "MembershipCredential";
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();

    [Fact]
    public void IssuerSignsStandardTopLevelVc2IdAndVerifierReleasesOnlyAuthenticatedId()
    {
        string signed = Issue(CredentialId);
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(signed));
        Assert.Equal(CredentialId.AbsoluteUri, payload.RootElement.GetProperty("id").GetString());
        Assert.Equal(_holder.Did,
            payload.RootElement.GetProperty("credentialSubject").GetProperty("id").GetString());
        Assert.Equal(7, payload.RootElement.EnumerateObject().Count());
        Assert.True(Vcdm20JoseCredential.TryVerifyWithId(
            signed, _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now,
            out var subject, out string? verifiedId));
        Assert.Equal(CredentialId.AbsoluteUri, verifiedId);
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        // The legacy six-field profile must not silently ignore a seventh signed field.
        Assert.False(Vcdm20JoseCredential.TryVerify(
            signed, _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void InvalidIdAndIncorrectIssuerSeedCannotBeIssued()
    {
        foreach (string invalid in new[]
        {
            "http://issuer.example/credentials/1",
            "https://user:password@issuer.example/credentials/1",
            "https://issuer.example/" + new string('a', 2100)
        })
        {
            Assert.Throws<ArgumentException>(() => Issue(new Uri(invalid)));
        }

        using var subject = Subject();
        Assert.Throws<ArgumentException>(() => Vcdm20JoseCredential.CreateWithId(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _other.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(10), CredentialId));
    }

    [Fact]
    public void WrongIssuerHolderExpiredAndTamperedIdNeverReleaseAuthenticatedValues()
    {
        string signed = Issue(CredentialId);
        var segments = signed.Split('.');
        string changedPayload = Ed25519JwtSigner.ExtractPayload(signed)
            .Replace("serial-12", "serial-99", StringComparison.Ordinal);
        Assert.NotEqual(Ed25519JwtSigner.ExtractPayload(signed), changedPayload);
        segments[1] = Base64UrlEncoder.Encode(changedPayload);
        foreach (var candidate in new[]
        {
            (Token: string.Join('.', segments), Issuer: _issuer.Did, Holder: _holder.Did, When: Now),
            (Token: signed, Issuer: _other.Did, Holder: _holder.Did, When: Now),
            (Token: signed, Issuer: _issuer.Did, Holder: _other.Did, When: Now),
            (Token: signed, Issuer: _issuer.Did, Holder: _holder.Did, When: Now.AddHours(1))
        })
        {
            Assert.False(Vcdm20JoseCredential.TryVerifyWithId(
                candidate.Token, candidate.Issuer, candidate.Holder, CredentialType, Vocabulary,
                candidate.When, out var deniedSubject, out string? deniedId));
            Assert.Equal(JsonValueKind.Undefined, deniedSubject.ValueKind);
            Assert.Null(deniedId);
        }
    }

    [Fact]
    public void IndependentlySignedUnrecognizedPolicyAndLegacyNoIdFailClosed()
    {
        string signed = Issue(CredentialId);
        string payload = Ed25519JwtSigner.ExtractPayload(signed);
        string changed = payload.Replace("\"id\":\"" + CredentialId.AbsoluteUri + "\"",
            "\"id\":{\"unexpected\":true}", StringComparison.Ordinal);
        Assert.NotEqual(payload, changed);
        string authenticButMalformed = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(signed), changed, _issuer.Seed);
        Assert.False(Vcdm20JoseCredential.TryVerifyWithId(
            authenticButMalformed, _issuer.Did, _holder.Did, CredentialType,
            Vocabulary, Now, out var claims, out string? id));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Null(id);

        using var subject = Subject();
        string withoutId = Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, _issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
        Assert.True(Vcdm20JoseCredential.TryVerify(withoutId, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));
        Assert.False(Vcdm20JoseCredential.TryVerifyWithId(withoutId, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out claims, out id));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Null(id);
    }

    private string Issue(Uri credentialId)
    {
        using var subject = Subject();
        return Vcdm20JoseCredential.CreateWithId(_issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, _issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10), credentialId);
    }

    private JsonDocument Subject() => JsonDocument.Parse(JsonSerializer.Serialize(
        new { id = _holder.Did, membership = "active" }));

    private static (byte[] Seed, string Did) NewIdentity()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] raw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        raw.CopyTo(encoded, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded));
    }
}
