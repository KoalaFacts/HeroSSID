using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// An independently trusted did:web assertion key does not imply that every
/// signed issuer name or credential identifier satisfies the verifier's policy.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebIssuerMetadataTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string KeyId = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private const string CredentialId = "https://issuer.example/credentials/123";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Identifier = new(CredentialId);
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IndependentlySignedNamedDidWebCredentialReleasesSubjectOnlyForAllExactPins()
    {
        var issuer = Identity();
        var holder = Identity();
        string original = SignIssuerJwt(issuer.Seed, holder.Did, IssuerName, CredentialId);

        Assert.True(Verify(original, issuer.PublicKey, holder.Did, IssuerName,
            Identifier, Now, out JsonElement subject));
        Assert.Equal(holder.Did, subject.GetProperty("id").GetString());
        Assert.Equal("member", subject.GetProperty("role").GetString());
    }

    [Fact]
    public void AuthenticSignaturesWithWrongNameOrCredentialIdCannotReleaseClaims()
    {
        var issuer = Identity();
        var other = Identity();
        var holder = Identity();
        string original = SignIssuerJwt(issuer.Seed, holder.Did, IssuerName, CredentialId);

        AssertRejected(original, issuer.PublicKey, holder.Did, "Different Organisation",
            Identifier, Now);
        AssertRejected(original, issuer.PublicKey, holder.Did, IssuerName,
            new Uri("https://issuer.example/credentials/456"), Now);
        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, "Different Organisation",
            CredentialId), issuer.PublicKey, holder.Did, IssuerName, Identifier, Now);
        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, IssuerName,
            "https://issuer.example/credentials/456"), issuer.PublicKey, holder.Did,
            IssuerName, Identifier, Now);
        AssertRejected(original, other.PublicKey, holder.Did, IssuerName, Identifier, Now);
        AssertRejected(original, issuer.PublicKey, other.Did, IssuerName, Identifier, Now);
        AssertRejected(original, issuer.PublicKey, holder.Did, IssuerName,
            Identifier, Now.AddMinutes(6));

        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, IssuerName,
            CredentialId, includeIssuerName: false), issuer.PublicKey, holder.Did,
            IssuerName, Identifier, Now);
        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, IssuerName,
            CredentialId, includeCredentialId: false), issuer.PublicKey, holder.Did,
            IssuerName, Identifier, Now);

        // A forged subject cannot become trusted by keeping the original
        // three-part JWT's signature but altering its signed payload.
        string[] parts = original.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(original).Replace(
                "member", "admin", StringComparison.Ordinal));
        AssertRejected(string.Join('.', parts), issuer.PublicKey, holder.Did,
            IssuerName, Identifier, Now);
    }

    private static void AssertRejected(string jwt, byte[] issuerPublicKey,
        string holderDid, string issuerName, Uri credentialId, DateTimeOffset now)
    {
        Assert.False(Verify(jwt, issuerPublicKey, holderDid, issuerName,
            credentialId, now, out JsonElement subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private static bool Verify(string jwt, byte[] issuerPublicKey,
        string holderDid, string issuerName, Uri credentialId, DateTimeOffset now,
        out JsonElement subject) =>
        JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
            jwt, IssuerDid, KeyId, issuerPublicKey, issuerName, credentialId,
            holderDid, CredentialType, Vocabulary, now, out subject);

    private static string SignIssuerJwt(byte[] seed, string holderDid,
        string issuerName, string credentialId, bool includeIssuerName = true,
        bool includeCredentialId = true)
    {
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "JWT",
            kid = KeyId
        });
        var vc = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1",
                Vocabulary.AbsoluteUri },
            ["type"] = new[] { "VerifiableCredential", CredentialType },
            ["credentialSubject"] = new { id = holderDid, role = "member" },
            ["issuer"] = includeIssuerName
                ? new { id = IssuerDid, name = issuerName }
                : (object)IssuerDid
        };
        if (includeCredentialId)
        {
            vc["id"] = credentialId;
        }

        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = IssuerDid,
            ["sub"] = holderDid,
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["vc"] = vc
        };
        if (includeCredentialId)
        {
            payload["jti"] = credentialId;
        }

        return Ed25519JwtSigner.CreateSignedJwt(header, JsonSerializer.Serialize(payload), seed);
    }

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
