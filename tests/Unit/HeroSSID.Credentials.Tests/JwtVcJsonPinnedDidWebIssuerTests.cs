using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Independently pinned did:web issuer key control is distinct from holder
/// control, domain ownership, legal identity and application authorization.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebIssuerTests
{
    private const string IssuerDid = "did:web:issuer.example";
    private const string CredentialType = "MembershipCredential";
    private const string KeyId = IssuerDid + "#key-1";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RealExternallySignedDidWebIssuerJwtIsVerifiedAgainstPreEnrolledPublicKey()
    {
        var issuer = Identity();
        var holder = Identity();
        string jwt = SignIssuerJwt(issuer.Seed, holder.Did, IssuerDid, KeyId);

        Assert.True(Verify(jwt, IssuerDid, KeyId, issuer.PublicKey, holder.Did, Now,
            out var subject));
        Assert.Equal(holder.Did, subject.GetProperty("id").GetString());
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Fact]
    public void DifferentTrustPinsOrSignaturesNeverReleaseClaims()
    {
        var issuer = Identity();
        var attacker = Identity();
        var holder = Identity();
        string jwt = SignIssuerJwt(issuer.Seed, holder.Did, IssuerDid, KeyId);

        AssertRejected(jwt, "did:web:other.example", KeyId, issuer.PublicKey, holder.Did, Now);
        AssertRejected(jwt, IssuerDid, IssuerDid + "#key-2", issuer.PublicKey, holder.Did, Now);
        AssertRejected(jwt, IssuerDid, KeyId, attacker.PublicKey, holder.Did, Now);
        AssertRejected(jwt, IssuerDid, KeyId, issuer.PublicKey, attacker.Did, Now);
        AssertRejected(jwt, "did:web:localhost", KeyId, issuer.PublicKey, holder.Did, Now);
        AssertRejected(jwt, IssuerDid, KeyId, issuer.PublicKey, holder.Did, Now.AddMinutes(6));

        // Even when the JWT has an authentic Ed25519 signature, a different
        // JOSE kid or a mismatched embedded VC issuer is not this enrolled key.
        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, IssuerDid,
            IssuerDid + "#key-2"), IssuerDid, KeyId, issuer.PublicKey, holder.Did, Now);
        AssertRejected(SignIssuerJwt(issuer.Seed, holder.Did, IssuerDid, KeyId,
            embeddedIssuerDid: "did:web:other.example"), IssuerDid, KeyId,
            issuer.PublicKey, holder.Did, Now);
        AssertRejected(SignIssuerJwt(attacker.Seed, holder.Did, IssuerDid, KeyId),
            IssuerDid, KeyId, issuer.PublicKey, holder.Did, Now);

        string[] parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(jwt).Replace(
                "active", "admin", StringComparison.Ordinal));
        AssertRejected(string.Join('.', parts), IssuerDid, KeyId,
            issuer.PublicKey, holder.Did, Now);
    }

    [Fact]
    public void ExistingDidKeyOnlyVerifierStillFailsClosedForDidWeb()
    {
        var issuer = Identity();
        var holder = Identity();
        string jwt = SignIssuerJwt(issuer.Seed, holder.Did, IssuerDid, KeyId);

        Assert.False(JwtVcJsonCredential.TryVerify(jwt, IssuerDid, holder.Did,
            CredentialType, Vocabulary, Now, out var subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private static void AssertRejected(string jwt, string issuerDid, string keyId,
        byte[] publicKey, string holderDid, DateTimeOffset now)
    {
        Assert.False(Verify(jwt, issuerDid, keyId, publicKey, holderDid, now,
            out var subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private static bool Verify(string jwt, string issuerDid, string keyId,
        byte[] publicKey, string holderDid, DateTimeOffset now,
        out JsonElement subject) =>
        JwtVcJsonPinnedDidWebIssuerVerifier.TryVerify(jwt, issuerDid, keyId,
            publicKey, holderDid, CredentialType, Vocabulary, now, out subject);

    private static string SignIssuerJwt(byte[] seed, string holderDid,
        string issuerDid, string keyId, string? embeddedIssuerDid = null)
    {
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "JWT",
            kid = keyId
        });
        var vc = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1",
                Vocabulary.AbsoluteUri },
            ["type"] = new[] { "VerifiableCredential", CredentialType },
            ["credentialSubject"] = new { id = holderDid, membership = "active" },
            ["issuer"] = embeddedIssuerDid ?? issuerDid
        };
        string payload = JsonSerializer.Serialize(new
        {
            iss = issuerDid,
            sub = holderDid,
            nbf = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            exp = Now.AddMinutes(5).ToUnixTimeSeconds(),
            vc
        });
        return Ed25519JwtSigner.CreateSignedJwt(header, payload, seed);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
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
