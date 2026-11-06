using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A real VC2 object issuer must remain revocable by its original Ed25519 signer.
/// Status does not independently authenticate a descriptive issuer name or holder.
/// </summary>
public sealed class Vcdm20NamedIssuerRevocationSnapshotTests
{
    private const string IssuerName = "Koala Facts Membership Issuer";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/context/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/123");

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void AuthenticNamedIssuerAndSignedIdCanBeReportedCleanAndRevoked()
    {
        string jwt = IssueNamedCredential();
        DateTimeOffset now = _clock.GetUtcNow();

        Assert.True(Vcdm20JoseCredential.TryVerifyNamedIssuerWithId(
            jwt, _issuer.Did, IssuerName, _holder.Did, CredentialType,
            Context, CredentialId, now, out JsonElement subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        string clean = Snapshot([]);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(clean, jwt, _issuer.Did, _clock.GetUtcNow()));

        string revoked = Snapshot([jwt]);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(revoked, jwt, _issuer.Did, _clock.GetUtcNow()));
    }

    [Fact]
    public void ForeignSignerAndMalformedAuthenticallySignedDescriptorCannotEnterStatus()
    {
        string jwt = IssueNamedCredential();
        var other = NewIdentity();
        string clean = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(clean, jwt, other.Did, _clock.GetUtcNow()));

        string alteredPayload = Ed25519JwtSigner.ExtractPayload(jwt).Replace(
            "\"name\":\"Koala Facts Membership Issuer\"",
            "\"name\":\" Koala Facts Membership Issuer \"",
            StringComparison.Ordinal);
        Assert.NotEqual(Ed25519JwtSigner.ExtractPayload(jwt), alteredPayload);
        string malformedButGenuinelySigned = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(jwt), alteredPayload, _issuer.Seed);

        Assert.Throws<CryptographicException>(() =>
            Vcdm20RevocationSnapshot.Create(_issuer.Did,
                [malformedButGenuinelySigned], _issuer.Seed,
                Observation(), _clock));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(clean,
                malformedButGenuinelySigned, _issuer.Did, _clock.GetUtcNow()));
    }

    [Fact]
    public void ExistingStringIssuerSignedIdRemainsRevocable()
    {
        using var claims = Subject();
        var now = _clock.GetUtcNow();
        string jwt = Vcdm20JoseCredential.CreateWithId(
            _issuer.Did, _holder.Did, CredentialType, Context,
            claims.RootElement, _issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(10), CredentialId);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(Snapshot([]), jwt, _issuer.Did, _clock.GetUtcNow()));
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(Snapshot([jwt]), jwt, _issuer.Did, _clock.GetUtcNow()));
    }

    private string IssueNamedCredential()
    {
        using var claims = Subject();
        DateTimeOffset now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.CreateWithNamedIssuerAndId(
            _issuer.Did, IssuerName, _holder.Did, CredentialType, Context,
            claims.RootElement, _issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(10), CredentialId);
    }

    private JsonDocument Subject() => JsonDocument.Parse(
        JsonSerializer.Serialize(new { id = _holder.Did, membership = "active" }));

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(_issuer.Did, revoked,
            _issuer.Seed, Observation(), _clock);

    private DateTimeOffset Observation() =>
        DateTimeOffset.FromUnixTimeSeconds(_clock.GetUtcNow().ToUnixTimeSeconds());

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
