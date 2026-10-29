using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;
using System.Text.Json;

namespace HeroSSID.Credentials.Tests;

public sealed class OfflineCredentialVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 29, 7, 0, 0, TimeSpan.Zero);
    private const string HolderDid = "did:key:zHolder";

    [Fact]
    public void GenuineIssuerAndCredentialCanBeCheckedWithoutIssuerDatabase()
    {
        var (privateKey, publicKey) = NewKey();
        string issuerDid = DidFromPublicKey(publicKey);
        string revoked = Credential(issuerDid, privateKey);
        string other = Credential(issuerDid, privateKey, sub: "did:key:zOther");
        string snapshot = IssuerRevocationSnapshot.Create(issuerDid, [revoked], privateKey, publicKey, Now);

        Assert.Equal(OfflineCredentialCheckResult.Revoked,
            OfflineCredentialVerifier.Check(revoked, snapshot, issuerDid, Now.AddSeconds(10)));
        Assert.Equal(OfflineCredentialCheckResult.SignedNotListed,
            OfflineCredentialVerifier.Check(other, snapshot, issuerDid, Now.AddSeconds(10)));
    }

    [Fact]
    public void RejectsForgedExpiredOrStructurallyInvalidIssuerCredential()
    {
        var (privateKey, publicKey) = NewKey();
        var (attackerPrivate, _) = NewKey();
        string issuerDid = DidFromPublicKey(publicKey);
        string snapshot = IssuerRevocationSnapshot.Create(issuerDid, [], privateKey, publicKey, Now);
        string forged = Credential(issuerDid, attackerPrivate);
        string expired = Credential(issuerDid, privateKey, expiresAt: Now.AddSeconds(-1).ToUnixTimeSeconds());
        string future = Credential(issuerDid, privateKey, issuedAt: Now.AddSeconds(20).ToUnixTimeSeconds());
        string notYetValid = Credential(issuerDid, privateKey, notBefore: Now.AddSeconds(20).ToUnixTimeSeconds());
        string wrongSubject = Credential(issuerDid, privateKey, subjectId: "did:key:zDifferent");
        string missingType = Credential(issuerDid, privateKey, includeBaseType: false);
        string missingSubject = Credential(issuerDid, privateKey, includeSubject: false);

        foreach (var credential in new[] { forged, expired, future, notYetValid, wrongSubject, missingType, missingSubject })
        {
            Assert.Equal(OfflineCredentialCheckResult.Invalid,
                OfflineCredentialVerifier.Check(credential, snapshot, issuerDid, Now));
        }
    }

    [Fact]
    public void RejectsUnboundDidKeyWrongTrustAnchorAndStaleSnapshot()
    {
        var (privateKey, publicKey) = NewKey();
        var (_, otherPublicKey) = NewKey();
        string issuerDid = DidFromPublicKey(publicKey);
        string credential = Credential(issuerDid, privateKey);
        string snapshot = IssuerRevocationSnapshot.Create(issuerDid, [], privateKey, publicKey, Now);
        string fakeIssuer = "did:key:zNotDerivedFromAnySigningKey";
        string fakeCredential = Credential(fakeIssuer, privateKey);
        string fakeSnapshot = IssuerRevocationSnapshot.Create(fakeIssuer, [], privateKey, publicKey, Now);

        Assert.Equal(OfflineCredentialCheckResult.Invalid,
            OfflineCredentialVerifier.Check(credential, snapshot, DidFromPublicKey(otherPublicKey), Now));
        Assert.Equal(OfflineCredentialCheckResult.Invalid,
            OfflineCredentialVerifier.Check(fakeCredential, fakeSnapshot, fakeIssuer, Now));
        Assert.Equal(OfflineCredentialCheckResult.Invalid,
            OfflineCredentialVerifier.Check(credential, snapshot, issuerDid, Now.AddSeconds(60)));
    }

    private static string DidFromPublicKey(byte[] publicKey)
    {
        byte[] codec = new byte[34];
        codec[0] = 0xed;
        codec[1] = 0x01;
        publicKey.CopyTo(codec, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(codec);
    }

    private static string Credential(
        string issuerDid,
        byte[] privateKey,
        string sub = HolderDid,
        long? issuedAt = null,
        long? expiresAt = null,
        long? notBefore = null,
        string? subjectId = HolderDid,
        bool includeBaseType = true,
        bool includeSubject = true)
    {
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = issuerDid,
            ["sub"] = sub,
            ["iat"] = issuedAt ?? Now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt ?? Now.AddMinutes(15).ToUnixTimeSeconds()
        };
        if (notBefore.HasValue)
        {
            payload["nbf"] = notBefore.Value;
        }

        var vc = new Dictionary<string, object?>();
        vc["type"] = includeBaseType ? new[] { "VerifiableCredential", "MembershipCredential" } : new[] { "MembershipCredential" };
        if (includeSubject)
        {
            vc["credentialSubject"] = new { id = subjectId, role = "member" };
        }

        payload["vc"] = vc;
        return Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(payload), privateKey);
    }

    private static (byte[] privateKey, byte[] publicKey) NewKey()
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, parameters);
        return (key.Export(KeyBlobFormat.RawPrivateKey), key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }
}
