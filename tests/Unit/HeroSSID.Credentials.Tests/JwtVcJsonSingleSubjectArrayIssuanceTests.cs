using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Single-element array is a valid W3C VC1.1 credentialSubject representation.
/// The issuer must preserve the exact signed array, even though the bounded
/// verifier returns its single object to legacy consumers.
/// </summary>
public sealed class JwtVcJsonSingleSubjectArrayIssuanceTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private const string CredentialType = "https://issuer.example/credentials#MemberCredential";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IssuerSignsSingleSubjectArrayWithoutUnwrappingOrRewritingHolder(bool includeSubjectId)
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        DateTimeOffset now = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
        object subject = includeSubjectId
            ? new { id = holder.Did, membership = "active" }
            : new { membership = "active" };
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new[] { subject }));

        string signed = JwtVcJsonCredential.CreateWithExactValidity(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            document.RootElement, issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5));

        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(signed));
        JsonElement encoded = payload.RootElement.GetProperty("vc")
            .GetProperty("credentialSubject");
        Assert.Equal(JsonValueKind.Array, encoded.ValueKind);
        Assert.Equal(1, encoded.GetArrayLength());
        Assert.Equal("active", encoded[0].GetProperty("membership").GetString());
        Assert.Equal(includeSubjectId, encoded[0].TryGetProperty("id", out _));
        Assert.True(JwtVcJsonCredential.TryVerify(signed, issuer.Did, holder.Did,
            CredentialType, Vocabulary, now, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(signed, outsider.Did, holder.Did,
            CredentialType, Vocabulary, now, out _));
        Assert.False(JwtVcJsonCredential.TryVerify(signed, issuer.Did, outsider.Did,
            CredentialType, Vocabulary, now, out _));

        string[] parts = signed.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(parts[1]).Replace(
                "active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts),
            issuer.Did, holder.Did, CredentialType, Vocabulary, now, out _));
    }

    [Fact]
    public void IssuerRejectsAmbiguousUnboundOrEmbeddedContextSubjectArrays()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        DateTimeOffset now = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
        string[] forbidden =
        [
            "[]",
            "[{},{}]",
            JsonSerializer.Serialize(new[] { new { id = outsider.Did, membership = "admin" } }),
            JsonSerializer.Serialize(new[] { new { id = "", membership = "admin" } }),
            "[{\"membership\":\"active\",\"nested\":{\"@context\":\"https://other.example/v1\"}}]",
            "{\"membership\":\"active\",\"nested\":{\"@context\":\"https://other.example/v1\"}}"
        ];
        foreach (string json in forbidden)
        {
            using var document = JsonDocument.Parse(json);
            Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
                issuer.Did, holder.Did, CredentialType, Vocabulary,
                document.RootElement, issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5)));
        }
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] rawPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        rawPublicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
