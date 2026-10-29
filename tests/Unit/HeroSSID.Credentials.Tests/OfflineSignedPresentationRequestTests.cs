using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OfflineSignedPresentationRequestTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid Tenant = Guid.Parse("43b2da72-460c-474a-a76d-f07e0d2437e4");
    private const string Audience = "https://verifier.example/present";
    private static readonly string[] CredentialTypes = ["VerifiableCredential", "MembershipCredential"];
    private readonly FixedClock _clock = new(Now);
    private readonly InMemoryPresentationChallengeStore _store;
    private readonly byte[] _verifierPrivate;
    private readonly byte[] _issuerPrivate;
    private readonly byte[] _holderPrivate;
    private readonly string _verifierDid;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public OfflineSignedPresentationRequestTests()
    {
        _store = new InMemoryPresentationChallengeStore(_clock);
        (_verifierPrivate, var verifierPublic) = NewKey();
        (_issuerPrivate, var issuerPublic) = NewKey();
        (_holderPrivate, var holderPublic) = NewKey();
        _verifierDid = DidFromKey(verifierPublic);
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void IndependentlyPinnedVerifierSignsRequestAndHolderCanPresentOnlyOnce()
    {
        var challenge = Issue();
        var signed = Sign(challenge);
        Assert.True(OfflineSignedPresentationRequest.TryRead(signed, _verifierDid, Audience, _clock, out var recovered));
        Assert.NotNull(recovered);
        Assert.Equal(challenge, recovered);

        var presentation = OfflineSignedPresentationRequest.CreatePresentation(
            signed, _verifierDid, Audience, Credential(), _holderDid, _holderPrivate, _clock);
        string snapshot = IssuerRevocationSnapshot.Create(_issuerDid, [],
            _issuerPrivate, DecodePublic(_issuerDid), _clock.GetUtcNow());
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OfflinePresentationVerifier.Check(presentation, snapshot, Tenant, Audience, challenge.Nonce, _store, _clock));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OfflinePresentationVerifier.Check(presentation, snapshot, Tenant, Audience, challenge.Nonce, _store, _clock));
    }

    [Fact]
    public void HolderRejectsWrongVerifierAndWrongAudienceBeforeDisclosing()
    {
        var signed = Sign(Issue());
        var (_, otherPublic) = NewKey();
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            signed, DidFromKey(otherPublic), Audience, _clock, out _));
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            signed, _verifierDid, "https://attacker.example/present", _clock, out _));
        Assert.Throws<ArgumentException>(() =>
            OfflineSignedPresentationRequest.CreatePresentation(signed, _verifierDid,
                "https://attacker.example/present", Credential(), _holderDid, _holderPrivate, _clock));
    }

    [Fact]
    public void HolderRejectsPayloadTamperingEvenWhenPinnedDidLooksRight()
    {
        var signed = Sign(Issue());
        var parts = signed.Split('.');
        var payload = Ed25519JwtSigner.ExtractPayload(signed);
        parts[1] = Base64UrlEncoder.Encode(payload.Replace(Audience, "https://attacker.example/present", StringComparison.Ordinal));
        var forged = string.Join('.', parts);
        Assert.False(OfflineSignedPresentationRequest.TryRead(forged, _verifierDid, Audience, _clock, out _));
    }

    [Fact]
    public void HolderRejectsAttackerSignatureImpersonatingPinnedVerifier()
    {
        var signed = Sign(Issue());
        var (attackerPrivate, _) = NewKey();
        var forged = Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"herossid-request+jwt\"}",
            Ed25519JwtSigner.ExtractPayload(signed), attackerPrivate);
        Assert.False(OfflineSignedPresentationRequest.TryRead(forged, _verifierDid, Audience, _clock, out _));
        Assert.Throws<ArgumentException>(() =>
            OfflineSignedPresentationRequest.CreatePresentation(
                forged, _verifierDid, Audience, Credential(), _holderDid, _holderPrivate, _clock));
    }

    [Fact]
    public void VerifierCannotSignWithPrivateKeyForOtherDid()
    {
        var (attackerPrivate, _) = NewKey();
        Assert.Throws<ArgumentException>(() =>
            OfflineSignedPresentationRequest.Create(Issue(), _verifierDid, attackerPrivate, _clock));
    }

    [Fact]
    public void HolderRejectsExpiredAndTooLongRequests()
    {
        var challenge = Issue();
        var signed = Sign(challenge);
        _clock.Advance(TimeSpan.FromMinutes(3));
        Assert.False(OfflineSignedPresentationRequest.TryRead(signed, _verifierDid, Audience, _clock, out _));

        Assert.Throws<ArgumentException>(() =>
            OfflineSignedPresentationRequest.Create(challenge with { ExpiresAt = _clock.GetUtcNow().AddMinutes(10) },
                _verifierDid, _verifierPrivate, _clock));
    }

    [Fact]
    public void SignedRequestEnforcesNonceTypeAndIssuedAtEvenWhenSignatureIsGenuine()
    {
        var signed = Sign(Issue());
        var fakeNonce = SignPayload(new
        {
            iss = _verifierDid, aud = Audience, nonce = "not-canonical",
            trustedIssuerDid = _issuerDid, iat = PresentationTime(Now), exp = PresentationTime(Now.AddMinutes(2))
        });
        Assert.False(OfflineSignedPresentationRequest.TryRead(fakeNonce, _verifierDid, Audience, _clock, out _));

        var future = SignPayload(new
        {
            iss = _verifierDid, aud = Audience, nonce = Issue().Nonce,
            trustedIssuerDid = _issuerDid, iat = PresentationTime(Now.AddSeconds(60)), exp = PresentationTime(Now.AddMinutes(2))
        });
        Assert.False(OfflineSignedPresentationRequest.TryRead(future, _verifierDid, Audience, _clock, out _));

        var wrongHeader = Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}",
            Ed25519JwtSigner.ExtractPayload(signed), _verifierPrivate);
        Assert.False(OfflineSignedPresentationRequest.TryRead(wrongHeader, _verifierDid, Audience, _clock, out _));
    }

    [Fact]
    public void FractionalExpiryIsPreservedAndOriginalIssuerStillRequired()
    {
        _clock.Advance(TimeSpan.FromMilliseconds(900));
        var challenge = _store.Issue(Tenant, Audience, _issuerDid, TimeSpan.FromSeconds(1));
        var signed = Sign(challenge);
        _clock.Advance(TimeSpan.FromMilliseconds(200));
        Assert.True(OfflineSignedPresentationRequest.TryRead(signed, _verifierDid, Audience, _clock, out var recovered));
        Assert.NotNull(recovered);
        Assert.Equal(challenge.ExpiresAt.UtcTicks, recovered.ExpiresAt.UtcTicks);

        var (attackerPrivate, _) = NewKey();
        string forgedCredential = Credential(attackerPrivate);
        Assert.Throws<ArgumentException>(() =>
            OfflineSignedPresentationRequest.CreatePresentation(
                signed, _verifierDid, Audience, forgedCredential, _holderDid, _holderPrivate, _clock));
        string valid = OfflineSignedPresentationRequest.CreatePresentation(
            signed, _verifierDid, Audience, Credential(), _holderDid, _holderPrivate, _clock);
        Assert.False(string.IsNullOrWhiteSpace(valid));
    }

    private PresentationChallenge Issue() => _store.Issue(Tenant, Audience, _issuerDid);

    private string Sign(PresentationChallenge challenge) =>
        OfflineSignedPresentationRequest.Create(challenge, _verifierDid, _verifierPrivate, _clock);

    private string SignPayload(object payload) =>
        Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"herossid-request+jwt\"}",
            JsonSerializer.Serialize(payload), _verifierPrivate);

    private string Credential(byte[]? signingKey = null) =>
        Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = _issuerDid, sub = _holderDid,
                iat = Now.ToUnixTimeSeconds(), exp = Now.AddMinutes(15).ToUnixTimeSeconds(),
                vc = new { type = CredentialTypes,
                    credentialSubject = new { id = _holderDid, membership = "active" } }
            }), signingKey ?? _issuerPrivate);

    private static decimal PresentationTime(DateTimeOffset time) =>
        (time.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / (decimal)TimeSpan.TicksPerSecond;

    private static byte[] DecodePublic(string did) =>
        SimpleBase.Base58.Bitcoin.Decode(did.AsSpan("did:key:z".Length)).AsSpan(2).ToArray();

    private static string DidFromKey(byte[] publicKey)
    {
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }

    private static (byte[] Private, byte[] Public) NewKey()
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, parameters);
        return (key.Export(KeyBlobFormat.RawPrivateKey), key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    private sealed class FixedClock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
