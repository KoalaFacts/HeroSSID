using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OfflinePresentationCreatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 29, 8, 30, 0, TimeSpan.Zero);
    private static readonly Guid VerifierTenant = Guid.Parse("b98c7e09-611f-4906-a0e2-9be1597a270d");
    private const string Audience = "https://verifier.example/present";
    private static readonly string[] Types = ["VerifiableCredential", "MembershipCredential"];

    private readonly FixedClock _clock = new(Now);
    private readonly InMemoryPresentationChallengeStore _challenges;
    private readonly byte[] _issuerPrivate;
    private readonly byte[] _holderPrivate;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public OfflinePresentationCreatorTests()
    {
        _challenges = new InMemoryPresentationChallengeStore(_clock);
        (_issuerPrivate, var issuerPublic) = NewKey();
        (_holderPrivate, var holderPublic) = NewKey();
        _issuerDid = DidFromKey(issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void IndependentHolderSignsFullCredentialAndVerifierConsumesOnce()
    {
        var request = NewRequest();
        string credential = Credential();
        string presentation = Create(request, credential);
        string snapshot = Snapshot();

        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OfflinePresentationVerifier.Check(presentation, snapshot, VerifierTenant,
                request.Audience, request.Nonce, _challenges, _clock));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OfflinePresentationVerifier.Check(presentation, snapshot, VerifierTenant,
                request.Audience, request.Nonce, _challenges, _clock));
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        Assert.Equal(credential, payload.RootElement.GetProperty("vp")
            .GetProperty("verifiableCredential")[0].GetString());
    }

    [Fact]
    public void RevocationStillWinsAgainstGenuineHolderSignature()
    {
        var request = NewRequest();
        string credential = Credential();
        string presentation = Create(request, credential);

        Assert.Equal(OfflinePresentationCheckResult.Revoked,
            OfflinePresentationVerifier.Check(presentation, Snapshot(credential), VerifierTenant,
                request.Audience, request.Nonce, _challenges, _clock));
    }

    [Fact]
    public void DifferentHolderPrivateKeyCannotMasqueradeAsCredentialSubject()
    {
        var request = NewRequest();
        string credential = Credential();
        var (attackerPrivate, _) = NewKey();

        Assert.Throws<ArgumentException>(() =>
            OfflinePresentationCreator.Create(request, credential, _holderDid, attackerPrivate, _clock));
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OfflinePresentationVerifier.Check(Create(request, credential), Snapshot(), VerifierTenant,
                request.Audience, request.Nonce, _challenges, _clock));
    }

    [Fact]
    public void RejectsDifferentSubjectAndDifferentTrustedIssuer()
    {
        var request = NewRequest();
        var (_, otherPublic) = NewKey();
        string otherHolder = DidFromKey(otherPublic);
        var (otherIssuerPrivate, otherIssuerPublic) = NewKey();
        string otherIssuer = DidFromKey(otherIssuerPublic);

        Assert.Throws<ArgumentException>(() => Create(request, Credential(holderDid: otherHolder)));
        Assert.Throws<ArgumentException>(() =>
            Create(request, Credential(issuerDid: otherIssuer, signingKey: otherIssuerPrivate)));
    }

    [Fact]
    public void RejectsForgeryEvenWhenIssuerAndHolderClaimsLookCorrect()
    {
        var request = NewRequest();
        var (attackerPrivate, _) = NewKey();
        Assert.Throws<ArgumentException>(() =>
            Create(request, Credential(signingKey: attackerPrivate)));
    }

    [Fact]
    public void RejectsExpiredRequestCredentialAndMalformedHolderKey()
    {
        var request = NewRequest();
        Assert.Throws<ArgumentException>(() =>
            Create(request, Credential(expiresAt: Now.AddSeconds(-1).ToUnixTimeSeconds())));
        Assert.Throws<ArgumentException>(() =>
            OfflinePresentationCreator.Create(request, Credential(), _holderDid, new byte[31], _clock));

        _clock.Advance(TimeSpan.FromMinutes(3));
        Assert.Throws<ArgumentException>(() => Create(request, Credential()));
    }

    [Fact]
    public void FractionalChallengeExpiryRemainsUsableWithoutRoundingDown()
    {
        _clock.Advance(TimeSpan.FromMilliseconds(900));
        var request = _challenges.Issue(VerifierTenant, Audience, _issuerDid, TimeSpan.FromSeconds(1));
        _clock.Advance(TimeSpan.FromMilliseconds(200));
        string credential = Credential();

        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OfflinePresentationVerifier.Check(Create(request, credential), Snapshot(), VerifierTenant,
                request.Audience, request.Nonce, _challenges, _clock));
    }

    private PresentationChallenge NewRequest() =>
        _challenges.Issue(VerifierTenant, Audience, _issuerDid);

    private string Create(PresentationChallenge request, string credential) =>
        OfflinePresentationCreator.Create(request, credential, _holderDid, _holderPrivate, _clock);

    private string Snapshot(params string[] revoked) =>
        IssuerRevocationSnapshot.Create(_issuerDid, revoked, _issuerPrivate,
            DecodePublic(_issuerDid), _clock.GetUtcNow());

    private string Credential(
        string? holderDid = null, string? issuerDid = null, byte[]? signingKey = null, long? expiresAt = null)
    {
        string holder = holderDid ?? _holderDid;
        return Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = issuerDid ?? _issuerDid,
                sub = holder,
                iat = Now.ToUnixTimeSeconds(),
                exp = expiresAt ?? Now.AddMinutes(15).ToUnixTimeSeconds(),
                vc = new { type = Types, credentialSubject = new { id = holder, role = "member" } }
            }), signingKey ?? _issuerPrivate);
    }

    private static byte[] DecodePublic(string did)
    {
        var decoded = SimpleBase.Base58.Bitcoin.Decode(did["did:key:z".Length..]);
        return decoded.AsSpan(2).ToArray();
    }

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
