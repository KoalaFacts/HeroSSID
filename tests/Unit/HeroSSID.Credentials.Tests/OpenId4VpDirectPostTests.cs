using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpDirectPostTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid VerifierTenant = Guid.Parse("f54331e6-bcf7-4ba9-bf5b-ac41cc241f51");
    private const string ResponseUri = "https://verifier.example/openid4vp/response";
    private static readonly string[] CredentialTypes = ["VerifiableCredential", "MembershipCredential"];
    private readonly Clock _clock = new(Now);
    private readonly InMemoryPresentationChallengeStore _store;
    private readonly byte[] _verifierSeed;
    private readonly byte[] _issuerSeed;
    private readonly byte[] _holderSeed;
    private readonly string _verifierDid;
    private readonly string _issuerDid;
    private readonly string _holderDid;

    public OpenId4VpDirectPostTests()
    {
        _store = new InMemoryPresentationChallengeStore(_clock);
        (_verifierSeed, var verifierKey) = NewKey();
        (_issuerSeed, var issuerKey) = NewKey();
        (_holderSeed, var holderKey) = NewKey();
        _verifierDid = DidFromKey(verifierKey);
        _issuerDid = DidFromKey(issuerKey);
        _holderDid = DidFromKey(holderKey);
    }

    [Fact]
    public void RealSeparateVerifierAndHolderKeysCompleteSignedDirectPostWithOneUseChallenge()
    {
        var issued = _store.Issue(VerifierTenant, ClientId, _issuerDid);
        string requestJwt = OpenId4VpDirectPost.CreateSignedRequest(
            issued, _verifierDid, _verifierSeed, ResponseUri, _clock);
        Assert.True(OpenId4VpDirectPost.TryReadSignedRequest(requestJwt, _verifierDid,
            ResponseUri, _clock, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(issued, parsed.Challenge);
        Assert.Equal(ClientId, parsed.ClientId);
        Assert.Equal(ResponseUri, parsed.ResponseUri);

        using (var request = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(requestJwt)))
        {
            Assert.Equal("vp_token", request.RootElement.GetProperty("response_type").GetString());
            Assert.Equal("direct_post", request.RootElement.GetProperty("response_mode").GetString());
            Assert.Equal("jwt_vc_json", request.RootElement.GetProperty("dcql_query")
                .GetProperty("credentials")[0].GetProperty("format").GetString());
        }

        string form = OpenId4VpDirectPost.CreateHolderResponseForm(
            requestJwt, _verifierDid, ResponseUri, Credential(), _holderDid, _holderSeed, _clock);
        Assert.Contains("vp_token=", form, StringComparison.Ordinal);
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OpenId4VpDirectPost.CheckResponseForm(form, Snapshot(), VerifierTenant,
                ClientId, issued.Nonce, _store, _clock));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OpenId4VpDirectPost.CheckResponseForm(form, Snapshot(), VerifierTenant,
                ClientId, issued.Nonce, _store, _clock));
    }

    [Fact]
    public void HolderRejectsForgedRequestAndUntrustedVerifierBeforeDisclosingCredential()
    {
        var issued = _store.Issue(VerifierTenant, ClientId, _issuerDid);
        string valid = Request(issued);
        Assert.False(OpenId4VpDirectPost.TryReadSignedRequest(valid, _issuerDid, ResponseUri, _clock, out _));
        var parts = valid.Split('.');
        string payload = Ed25519JwtSigner.ExtractPayload(valid);
        parts[1] = Base64UrlEncoder.Encode(payload.Replace(ResponseUri,
            "https://attacker.example/collect", StringComparison.Ordinal));
        Assert.False(OpenId4VpDirectPost.TryReadSignedRequest(
            string.Join('.', parts), _verifierDid, ResponseUri, _clock, out _));
        Assert.Throws<ArgumentException>(() => OpenId4VpDirectPost.CreateHolderResponseForm(
            valid, _issuerDid, ResponseUri, Credential(), _holderDid, _holderSeed, _clock));
    }

    [Fact]
    public void HolderRequiresIndependentlyPinnedHttpsDestinationAndExactIssuerAndKey()
    {
        string requestJwt = Request(_store.Issue(VerifierTenant, ClientId, _issuerDid));
        Assert.False(OpenId4VpDirectPost.TryReadSignedRequest(requestJwt, _verifierDid,
            "https://attacker.example/collect", _clock, out _));
        Assert.Throws<ArgumentException>(() => OpenId4VpDirectPost.CreateHolderResponseForm(
            requestJwt, _verifierDid, ResponseUri, Credential(signingKey: _holderSeed),
            _holderDid, _holderSeed, _clock));
        var (attackerSeed, _) = NewKey();
        Assert.Throws<ArgumentException>(() => OpenId4VpDirectPost.CreateHolderResponseForm(
            requestJwt, _verifierDid, ResponseUri, Credential(),
            _holderDid, attackerSeed, _clock));
        Assert.Throws<ArgumentException>(() => OpenId4VpDirectPost.CreateSignedRequest(
            _store.Issue(VerifierTenant, ClientId, _issuerDid), _verifierDid,
            _verifierSeed, "http://verifier.example/collect", _clock));
    }

    [Fact]
    public void ExpiredSignedRequestCannotBeUsedByHolder()
    {
        string signed = Request(_store.Issue(VerifierTenant, ClientId, _issuerDid,
            TimeSpan.FromSeconds(1)));
        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.False(OpenId4VpDirectPost.TryReadSignedRequest(signed, _verifierDid,
            ResponseUri, _clock, out _));
        Assert.Throws<ArgumentException>(() => OpenId4VpDirectPost.CreateHolderResponseForm(
            signed, _verifierDid, ResponseUri, Credential(), _holderDid, _holderSeed, _clock));
    }

    [Fact]
    public void WrongStateTenantOrMalformedFormFailsWithoutConsumingValidResponse()
    {
        var issued = _store.Issue(VerifierTenant, ClientId, _issuerDid);
        string form = OpenId4VpDirectPost.CreateHolderResponseForm(
            Request(issued), _verifierDid, ResponseUri, Credential(), _holderDid, _holderSeed, _clock);
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OpenId4VpDirectPost.CheckResponseForm(form.Replace(issued.Nonce,
                "wrong-state", StringComparison.Ordinal), Snapshot(), VerifierTenant,
                ClientId, issued.Nonce, _store, _clock));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OpenId4VpDirectPost.CheckResponseForm(form + "&state=duplicate", Snapshot(),
                VerifierTenant, ClientId, issued.Nonce, _store, _clock));
        Assert.Equal(OfflinePresentationCheckResult.Invalid,
            OpenId4VpDirectPost.CheckResponseForm(form, Snapshot(), Guid.NewGuid(),
                ClientId, issued.Nonce, _store, _clock));
        Assert.Equal(OfflinePresentationCheckResult.SignedNotListed,
            OpenId4VpDirectPost.CheckResponseForm(form, Snapshot(), VerifierTenant,
                ClientId, issued.Nonce, _store, _clock));
    }

    [Fact]
    public void AuthenticIssuerRevocationIsRejectedEvenWithGenuineHolderProof()
    {
        var issued = _store.Issue(VerifierTenant, ClientId, _issuerDid);
        string credential = Credential();
        string form = OpenId4VpDirectPost.CreateHolderResponseForm(
            Request(issued), _verifierDid, ResponseUri, credential, _holderDid, _holderSeed, _clock);
        Assert.Equal(OfflinePresentationCheckResult.Revoked,
            OpenId4VpDirectPost.CheckResponseForm(form, Snapshot(credential), VerifierTenant,
                ClientId, issued.Nonce, _store, _clock));
    }

    private string ClientId => "decentralized_identifier:" + _verifierDid;

    private string Request(PresentationChallenge challenge) =>
        OpenId4VpDirectPost.CreateSignedRequest(challenge, _verifierDid,
            _verifierSeed, ResponseUri, _clock);

    private string Snapshot(params string[] revoked) =>
        IssuerRevocationSnapshot.Create(_issuerDid, revoked, _issuerSeed,
            DecodePublic(_issuerDid), _clock.GetUtcNow());

    private string Credential(byte[]? signingKey = null) =>
        Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new
            {
                iss = _issuerDid, sub = _holderDid,
                iat = Now.ToUnixTimeSeconds(), exp = Now.AddMinutes(15).ToUnixTimeSeconds(),
                vc = new
                {
                    @context = new[] { "https://www.w3.org/2018/credentials/v1" },
                    type = CredentialTypes,
                    credentialSubject = new { id = _holderDid, membership = "active" }
                }
            }), signingKey ?? _issuerSeed);

    private static byte[] DecodePublic(string did) =>
        SimpleBase.Base58.Bitcoin.Decode(did.AsSpan("did:key:z".Length)).AsSpan(2).ToArray();

    private static string DidFromKey(byte[] publicKey)
    {
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec);
    }

    private static (byte[] Seed, byte[] PublicKey) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    private sealed class Clock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
