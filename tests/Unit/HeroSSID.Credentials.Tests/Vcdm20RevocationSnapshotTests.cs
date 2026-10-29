using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20RevocationSnapshotTests
{
    private const string Audience = "https://verifier.example/check";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void RealIssuerSnapshotDistinguishesRevokedAndNotListedVc2()
    {
        var now = _clock.GetUtcNow();
        string revoked = Issue("revoked");
        string notListed = Issue("active");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [revoked], _issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(snapshot, revoked, _issuer.Did, now));
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(snapshot, notListed, _issuer.Did, now));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(snapshot, notListed, _issuer.Did, now.AddSeconds(61)));
    }

    [Fact]
    public void WrongIssuerTamperingOrForeignRevocationFailsClosed()
    {
        var now = _clock.GetUtcNow();
        string credential = Issue("active");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, now, _clock);
        var foreign = NewIdentity();
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(snapshot, credential, foreign.Did, now));
        var pieces = snapshot.Split('.');
        pieces[1] = Base64UrlEncoder.Encode("{}");
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(string.Join('.', pieces), credential, _issuer.Did, now));
        string forged = Vcdm20JoseCredential.Create(foreign.Did, _holder.Did, Type,
            Context, Subject("forged"), foreign.Seed, now.AddMinutes(-1), now.AddMinutes(10));
        Assert.Throws<CryptographicException>(() =>
            Vcdm20RevocationSnapshot.Create(_issuer.Did, [forged], _issuer.Seed, now, _clock));
    }

    [Fact]
    public void OversizedAndStaleOrFutureSnapshotsRefuseIssuance()
    {
        string credential = Issue("active");
        var now = _clock.GetUtcNow();
        var oversized = Enumerable.Repeat(credential, 257).ToArray();
        Assert.Throws<ArgumentException>(() =>
            Vcdm20RevocationSnapshot.Create(_issuer.Did, oversized, _issuer.Seed, now, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20RevocationSnapshot.Create(_issuer.Did, [credential], _issuer.Seed, now.AddMinutes(-2), _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20RevocationSnapshot.Create(_issuer.Did, [credential], _issuer.Seed, now.AddMinutes(1), _clock));
    }

    [Fact]
    public void OfflinePresentationChecksStatusAndConsumesChallengeWithoutDisclosingRevokedClaims()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        string credential = Issue("revoked");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, _clock.GetUtcNow(), _clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string presentation = Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
            credential, Type, Context, _holder.Did, _holder.Seed, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.CheckPresentation(presentation, snapshot, tenant,
                Audience, challenge.Nonce, Type, Context, store, _clock, out var revokedClaims));
        Assert.Equal(JsonValueKind.Undefined, revokedClaims.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentation(presentation, snapshot, tenant,
                Audience, challenge.Nonce, Type, Context, store, _clock, out _));
    }

    [Fact]
    public void OfflinePresentationReturnsClaimsOnlyForSignedNotListedAndRejectsOtherTenant()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        string credential = Issue("active");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, _clock.GetUtcNow(), _clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string presentation = Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
            credential, Type, Context, _holder.Did, _holder.Seed, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentation(presentation, snapshot, Guid.NewGuid(),
                Audience, challenge.Nonce, Type, Context, store, _clock, out var foreignClaims));
        Assert.Equal(JsonValueKind.Undefined, foreignClaims.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentation(presentation, snapshot, tenant,
                Audience, challenge.Nonce, Type, Context, store, _clock, out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    private string Issue(string membership)
    {
        var now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, Type, Context,
            Subject(membership), _issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10));
    }

    private JsonElement Subject(string membership) =>
        JsonSerializer.SerializeToElement(new { id = _holder.Did, membership });

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
