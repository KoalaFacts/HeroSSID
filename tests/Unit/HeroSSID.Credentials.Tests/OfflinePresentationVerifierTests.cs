using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OfflinePresentationVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 29, 7, 0, 0, TimeSpan.Zero);
    private static readonly Guid VerifierTenant = Guid.Parse("b4f3ccf9-2dbb-41b4-8d42-a98b1105042e");
    private const string Audience = "https://verifier.example/check";
    private readonly MutableClock _clock = new(Now);
    private readonly InMemoryPresentationChallengeStore _challenges;
    private readonly byte[] _issuerPrivate;
    private readonly byte[] _issuerPublic;
    private readonly byte[] _holderPrivate;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public OfflinePresentationVerifierTests()
    {
        _challenges = new InMemoryPresentationChallengeStore(_clock);
        (_issuerPrivate, _issuerPublic) = NewKey();
        (_holderPrivate, var holderPublic) = NewKey();
        _issuerDid = DidFromKey(_issuerPublic);
        _holderDid = DidFromKey(holderPublic);
    }

    [Fact]
    public void ValidIndependentHolderProofConsumesChallengeOnlyOnce()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var presentation = Envelope(credential, challenge);
        var snapshot = Snapshot();

        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed, Check(presentation, snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.Invalid, Check(presentation, snapshot, challenge));
    }

    [Fact]
    public void AuthenticatedRevocationCannotBeAcceptedAsUnrevoked()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var snapshot = Snapshot(credential);
        Assert.Equal(OfflinePresentationCheckResult.Revoked, Check(Envelope(credential, challenge), snapshot, challenge));
    }

    [Fact]
    public void ForgedHolderSignatureOrDifferentCredentialHolderFailsWithoutBurningChallenge()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var snapshot = Snapshot();
        var (attackerPrivate, _) = NewKey();

        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge, signingKey: attackerPrivate), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(Credential(holderDid: "did:key:zDifferent"), challenge), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            Check(Envelope(credential, challenge), snapshot, challenge));
    }

    [Fact]
    public void WrongNonceAudienceAndVerifierTenantFailWithoutBurningIssuedChallenge()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var snapshot = Snapshot();
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge, nonce: new string('A', 43)), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge, audience: "https://attacker.example"), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OfflinePresentationVerifier.Check(Envelope(credential, challenge), snapshot, Guid.NewGuid(),
                Audience, challenge.Nonce, _challenges, _clock));
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            Check(Envelope(credential, challenge), snapshot, challenge));
    }

    [Fact]
    public void ForgedIssuerCredentialOrExpiredSnapshotFailsBeforeConsumingChallenge()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var snapshot = Snapshot();
        var (attackerPrivate, _) = NewKey();
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(Credential(signingKey: attackerPrivate), challenge), snapshot, challenge));
        _clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            Check(Envelope(credential, challenge), Snapshot(), challenge));
    }

    [Fact]
    public void ExpiredRequestAndFutureOrExcessivePresentationLifetimeFail()
    {
        var challenge = NewChallenge();
        var credential = Credential();
        var snapshot = Snapshot();
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge, issuedAt: Now.AddSeconds(10).ToUnixTimeSeconds()), snapshot, challenge));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge, expiresAt: Now.AddMinutes(10).ToUnixTimeSeconds()), snapshot, challenge));
        _clock.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            Check(Envelope(credential, challenge), Snapshot(), challenge));
    }

    private PresentationChallenge NewChallenge() => _challenges.Issue(VerifierTenant, Audience, _issuerDid);

    private OfflinePresentationCheckResult Check(string presentation, string snapshot, PresentationChallenge challenge) =>
        OfflinePresentationVerifier.Check(presentation, snapshot, VerifierTenant, Audience, challenge.Nonce, _challenges, _clock);

    private string Snapshot(params string[] revoked) =>
        IssuerRevocationSnapshot.Create(_issuerDid, revoked, _issuerPrivate, _issuerPublic, _clock.GetUtcNow());

    private string Credential(string? holderDid = null, byte[]? signingKey = null)
    {
        string holder = holderDid ?? _holderDid;
        return Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = _issuerDid,
                sub = holder,
                iat = Now.ToUnixTimeSeconds(),
                exp = Now.AddMinutes(15).ToUnixTimeSeconds(),
                vc = new { type = new[] { "VerifiableCredential", "MembershipCredential" },
                    credentialSubject = new { id = holder, role = "member" } }
            }), signingKey ?? _issuerPrivate);
    }

    private string Envelope(string credential, PresentationChallenge challenge, byte[]? signingKey = null,
        string? audience = null, string? nonce = null, long? issuedAt = null, long? expiresAt = null) =>
        Ed25519JwtSigner.CreateSignedJwt(
            "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = _holderDid,
                aud = audience ?? Audience,
                nonce = nonce ?? challenge.Nonce,
                iat = issuedAt ?? Now.ToUnixTimeSeconds(),
                exp = expiresAt ?? challenge.ExpiresAt.ToUnixTimeSeconds(),
                vp = new { verifiableCredential = new[] { credential } }
            }), signingKey ?? _holderPrivate);

    private static string DidFromKey(byte[] publicKey)
    {
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec);
    }

    private static (byte[] Private, byte[] Public) NewKey()
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, parameters);
        return (key.Export(KeyBlobFormat.RawPrivateKey), key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    private sealed class MutableClock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _current = initial;
        public override DateTimeOffset GetUtcNow() => _current;
        public void Advance(TimeSpan duration) => _current = _current.Add(duration);
    }
}
