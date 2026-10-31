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
    public void StatusVerifierAcceptsOptionalVcCtyAndRejectsAuthenticWrongCty()
    {
        var now = _clock.GetUtcNow();
        string credential = Issue("active");
        string header = Ed25519JwtSigner.ExtractHeader(credential);
        string payload = Ed25519JwtSigner.ExtractPayload(credential);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, now, _clock);

        // A genuine issuer can accidentally emit the wrong profile kind.
        // Signing that malformed header cannot make it a legitimate direct VC2.
        string wrongHeader = header.Replace(
            "\"cty\":\"vc\"", "\"cty\":\"vp\"", StringComparison.Ordinal);
        Assert.NotEqual(header, wrongHeader);
        string wrong = Ed25519JwtSigner.CreateSignedJwt(wrongHeader, payload, _issuer.Seed);
        Assert.Throws<CryptographicException>(() =>
            Vcdm20RevocationSnapshot.Create(
                _issuer.Did, [wrong], _issuer.Seed, now, _clock));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(snapshot, wrong, _issuer.Did, now));

        // cty is optional in the Recommendation: older genuine direct VC2
        // tokens can still be listed and checked by the private snapshot.
        using var parsedHeader = JsonDocument.Parse(header);
        string legacyHeader = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "vc+jwt",
            kid = parsedHeader.RootElement.GetProperty("kid").GetString()
        });
        string legacy = Ed25519JwtSigner.CreateSignedJwt(
            legacyHeader, payload, _issuer.Seed);
        string oldSnapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [legacy], _issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(oldSnapshot, legacy, _issuer.Did, now));
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentVerifierRefusesPreCutoffAuthenticStatus(bool revoked)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string credential = Issue("member");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, revoked ? [credential] : [], _issuer.Seed,
            now.AddSeconds(-25), _clock);

        // The existing 60-second check accepts both authentic old states.
        Assert.Equal(revoked ? Vcdm20RevocationCheckResult.Revoked :
            Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(snapshot, credential, _issuer.Did, now));

        // The relying party learned of an incident ten seconds ago and must
        // refuse even a signed clean status observed before that incident.
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckAfterVerifierCutoff(snapshot, credential, now, now.AddSeconds(-10)));
    }

    [Fact]
    public void NewIssuerObservationPassesVerifierCutoffAndFutureCutoffIsDenied()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string credential = Issue("member");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            CheckAfterVerifierCutoff(snapshot, credential, now, now.AddSeconds(-10)));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckAfterVerifierCutoff(snapshot, credential, now, now.AddSeconds(1)));
    }

    private Vcdm20RevocationCheckResult CheckAfterVerifierCutoff(
        string snapshot, string credential, DateTimeOffset now, DateTimeOffset minimumObservedAt) =>
        Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
            snapshot, credential, _issuer.Did, now, minimumObservedAt);

    [Fact]
    public void FractionalSecondCutoffNeverRoundsBackwardToAcceptOlderStatus()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string credential = Issue("member");
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, now, _clock);

        // Signed iat is recorded only to seconds. Never silently round a
        // caller's fractional-second cutoff backward to trust older status.
        DateTimeOffset cutoff = DateTimeOffset
            .FromUnixTimeSeconds(now.ToUnixTimeSeconds()).AddTicks(1);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckAfterVerifierCutoff(snapshot, credential, now, cutoff));
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
