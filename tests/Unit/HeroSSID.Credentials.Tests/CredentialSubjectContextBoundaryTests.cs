using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A genuine issuer signature does not make a nested JSON-LD vocabulary
/// override safe. Both opt-in JWT credential profiles pin only the outer
/// context, so embedded contexts must fail closed before claims are released.
/// </summary>
public sealed class CredentialSubjectContextBoundaryTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 8, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType = "MembershipCredential";
    private const string ShadowVocabulary = "https://attacker.example/contexts/roles";
    private const string OriginalMember = "\"membership\":\"active\"";

    private readonly (byte[] Seed, byte[] PublicKey, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, byte[] PublicKey, string Did) _holder = NewIdentity();

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public void GenuineIssuerSignatureCannotShadowPinnedSubjectVocabulary(
        bool directVcdm20, bool nestedInArray)
    {
        using var subject = CleanSubject();
        string genuine = Issue(directVcdm20, subject.RootElement);
        Assert.True(Verify(directVcdm20, genuine, out _));

        string originalPayload = Ed25519JwtSigner.ExtractPayload(genuine);
        string shadowedMember = nestedInArray
            ? "\"membership\":\"active\",\"history\":[{\"@context\":{\"membership\":\"" + ShadowVocabulary + "\"},\"membership\":\"admin\"}]"
            : "\"membership\":\"active\",\"@context\":{\"membership\":\"" + ShadowVocabulary + "\"}";
        Assert.Contains(OriginalMember, originalPayload, StringComparison.Ordinal);
        string shadowPayload = originalPayload.Replace(
            OriginalMember, shadowedMember, StringComparison.Ordinal);
        string signedShadow = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(genuine), shadowPayload, _issuer.Seed);

        // This is an authentic *issuer*-signed credential, not a tampered JWT.
        Assert.True(Ed25519JwtSigner.VerifySignedJwt(signedShadow, _issuer.PublicKey));
        Assert.False(Verify(directVcdm20, signedShadow, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IssuerCannotCreateAContextShadowedCredential(bool directVcdm20)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["id"] = _holder.Did,
                ["membership"] = "active",
                ["@context"] = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["membership"] = ShadowVocabulary
                }
            }));
        Assert.Throws<ArgumentException>(() =>
            Issue(directVcdm20, subject.RootElement));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void OrdinaryNestedSubjectClaimsRemainSupported(bool directVcdm20)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _holder.Did,
            membership = "active",
            history = new[] { new { year = 2026, level = "member" } }
        }));
        string jwt = Issue(directVcdm20, subject.RootElement);
        Assert.True(Verify(directVcdm20, jwt, out JsonElement verified));
        Assert.Equal("member", verified.GetProperty("history")[0]
            .GetProperty("level").GetString());
    }

    private JsonDocument CleanSubject() => JsonDocument.Parse(
        JsonSerializer.Serialize(new { id = _holder.Did, membership = "active" }));

    private string Issue(bool directVcdm20, JsonElement subject) =>
        directVcdm20
            ? Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did,
                CredentialType, Vocabulary, subject, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(5))
            : JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
                CredentialType, Vocabulary, subject, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(5));

    private bool Verify(bool directVcdm20, string jwt, out JsonElement verified) =>
        directVcdm20
            ? Vcdm20JoseCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
                CredentialType, Vocabulary, Now, out verified)
            : JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
                CredentialType, Vocabulary, Now, out verified);

    private static (byte[] Seed, byte[] PublicKey, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
