using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;
using System.Text.Json;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerRevocationSnapshotTests
{
    private const string Issuer = "did:key:zIssuer";
    private const string OtherIssuer = "did:key:zOtherIssuer";
    private const string Holder = "did:key:zHolder";
    private static readonly DateTimeOffset Now = new(2026, 10, 29, 7, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SignedRevocationSnapshotWorksOfflineAndNeverCallsNotListedValid()
    {
        var (privateKey, publicKey) = NewKey();
        var revoked = Credential(Issuer, Holder, privateKey);
        var notRevoked = Credential(Issuer, "did:key:zAnotherHolder", privateKey);
        var snapshot = IssuerRevocationSnapshot.Create(Issuer, [revoked], privateKey, publicKey, Now);

        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            IssuerRevocationSnapshot.Check(snapshot, revoked, Issuer, publicKey, Now.AddSeconds(30)));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            IssuerRevocationSnapshot.Check(snapshot, notRevoked, Issuer, publicKey, Now.AddSeconds(30)));
    }

    [Fact]
    public void TamperedSnapshotWrongKeyIssuerOrExpiredSnapshotFailClosed()
    {
        var (privateKey, publicKey) = NewKey();
        var (_, anotherPublicKey) = NewKey();
        var jwt = Credential(Issuer, Holder, privateKey);
        var snapshot = IssuerRevocationSnapshot.Create(Issuer, [jwt], privateKey, publicKey, Now);
        var pieces = snapshot.Split('.');
        var tampered = pieces[0] + "." + Base64UrlEncoder.Encode("{\"iss\":\"did:key:attacker\"}") + "." + pieces[2];

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(tampered, jwt, Issuer, publicKey, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, jwt, Issuer, anotherPublicKey, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, jwt, OtherIssuer, publicKey, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, jwt, Issuer, publicKey, Now.AddSeconds(60)));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, jwt, Issuer, publicKey, Now.AddSeconds(-1)));
    }

    [Fact]
    public void UntrustedCredentialCannotUseIssuerSnapshotEvenWhenNotListed()
    {
        var (privateKey, publicKey) = NewKey();
        var (attackerKey, _) = NewKey();
        var valid = Credential(Issuer, Holder, privateKey);
        var forged = Credential(Issuer, Holder, attackerKey);
        var wrongIssuer = Credential(OtherIssuer, Holder, privateKey);
        var snapshot = IssuerRevocationSnapshot.Create(Issuer, [valid], privateKey, publicKey, Now);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, forged, Issuer, publicKey, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(snapshot, wrongIssuer, Issuer, publicKey, Now));
    }

    [Fact]
    public void RefusesInvalidStoredCredentialsAndIncompleteSnapshots()
    {
        var (privateKey, publicKey) = NewKey();
        var (otherKey, _) = NewKey();
        var wrongKey = Credential(Issuer, Holder, otherKey);
        var wrongIssuer = Credential(OtherIssuer, Holder, privateKey);
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            IssuerRevocationSnapshot.Create(Issuer, [wrongKey], privateKey, publicKey, Now));
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            IssuerRevocationSnapshot.Create(Issuer, [wrongIssuer], privateKey, publicKey, Now));
        var oversized = Enumerable.Repeat(Credential(Issuer, Holder, privateKey),
            IssuerRevocationSnapshot.MaximumEntries + 1).ToArray();
        Assert.Throws<ArgumentException>(() =>
            IssuerRevocationSnapshot.Create(Issuer, oversized, privateKey, publicKey, Now));
    }

    [Fact]
    public void SignedMalformedDuplicateOrUnsortedDigestListIsRejected()
    {
        var (privateKey, publicKey) = NewKey();
        var credential = Credential(Issuer, Holder, privateKey);
        var header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = "herossid-revocation-snapshot+jwt" });
        var malformed = Ed25519JwtSigner.CreateSignedJwt(header,
            "{\"version\":1,\"iss\":\"did:key:zIssuer\",\"iat\":1793257200,\"exp\":1793257260,\"revoked\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}",
            privateKey);
        var duplicate = Ed25519JwtSigner.CreateSignedJwt(header,
            "{\"version\":1,\"iss\":\"did:key:zIssuer\",\"iss\":\"did:key:zIssuer\",\"iat\":1793257200,\"exp\":1793257260,\"revoked\":[]}",
            privateKey);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(malformed, credential, Issuer, publicKey, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            IssuerRevocationSnapshot.Check(duplicate, credential, Issuer, publicKey, Now));
    }

    private static string Credential(string issuer, string holder, byte[] key) =>
        Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new { iss = issuer, sub = holder, iat = Now.ToUnixTimeSeconds(),
                vc = new { type = new[] { "VerifiableCredential", "MembershipCredential" },
                    credentialSubject = new { member = true } } }),
            key);

    private static (byte[] privateKey, byte[] publicKey) NewKey()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(algorithm, options);
        return (key.Export(KeyBlobFormat.RawPrivateKey), key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }
}
