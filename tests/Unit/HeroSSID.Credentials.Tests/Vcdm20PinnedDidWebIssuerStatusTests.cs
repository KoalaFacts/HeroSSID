using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20PinnedDidWebIssuerStatusTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/42");
    private static readonly Uri Audience = new("https://verifier.example/check");
    private static readonly Uri Context = new("https://issuer.example/vocab/member");

    [Fact]
    public void SameIssuerStatusAuthenticatesExactOriginalAndRejectsRevokedAndReplayOfOldSnapshot()
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string credential = Issue(issuer, holder.Did, now);
        string clean = Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey, IssuerName,
            [], now.AddSeconds(-1), TimeProvider.System);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Check(clean, credential, issuer.PublicKey, holder.Did,
                now.AddSeconds(-2), now, out JsonElement claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        string revoked = Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey, IssuerName,
            [credential], now.AddSeconds(-1), TimeProvider.System);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Check(revoked, credential, issuer.PublicKey, holder.Did,
                now.AddSeconds(-2), now, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(clean, credential, issuer.PublicKey, holder.Did,
                now.AddSeconds(1), now.AddSeconds(1), out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(clean, credential, issuer.PublicKey, holder.Did,
                now.AddSeconds(-2), now.AddSeconds(61), out denied));
    }

    [Fact]
    public void ForeignSignerAndTamperedCredentialCannotYieldStatusOrClaims()
    {
        var issuer = Identity();
        var attacker = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string original = Issue(issuer, holder.Did, now);
        string clean = Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey, IssuerName,
            [], now.AddSeconds(-1), TimeProvider.System);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(clean, original, attacker.PublicKey, holder.Did,
                now.AddSeconds(-2), now, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(clean, original + "a", issuer.PublicKey, holder.Did,
                now.AddSeconds(-2), now, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.ThrowsAny<Exception>(() => Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, IssuerDid + "#key-1", attacker.Seed, issuer.PublicKey, IssuerName,
            [original], now.AddSeconds(-1), TimeProvider.System));
        Assert.ThrowsAny<Exception>(() => Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey, IssuerName,
            [original + "a"], now.AddSeconds(-1), TimeProvider.System));
    }

    private static Vcdm20RevocationCheckResult Check(
        string snapshot, string jwt, byte[] key, string holderDid,
        DateTimeOffset cutoff, DateTimeOffset now, out JsonElement claims) =>
        Vcdm20PinnedDidWebIssuerStatus.Check(snapshot, jwt, IssuerDid,
            IssuerDid + "#key-1", key, IssuerName, CredentialId, Audience,
            holderDid, "MembershipCredential", Context, cutoff, now, out claims);

    private static string Issue((byte[] Seed, byte[] PublicKey, string Did) issuer,
        string holderDid, DateTimeOffset now)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, membership = "active" }));
        return Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
            IssuerDid, IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holderDid, "MembershipCredential", Context,
            subject.RootElement, now.AddMinutes(-1), now.AddMinutes(10));
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
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
