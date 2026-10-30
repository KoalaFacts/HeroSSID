using System.Net;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpJwtVcJsonDirectPostTests
{
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri SubjectContext = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri ResponseUri = new("https://verifier.example/oid4vp/direct-post");
    private static readonly DateTimeOffset StartingTime = new(2026, 10, 30, 10, 0, 0, TimeSpan.Zero);
    private readonly FakeClock _clock = new(StartingTime);
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();
    private string Audience => "decentralized_identifier:" + _verifier.Did;

    [Fact]
    public void IndependentKeysCompleteJwtVcJsonDirectPostAndRejectReplay()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = Request(challenge);

        Assert.True(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext, _clock, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(challenge, parsed.Challenge);
        Assert.Equal(Audience, parsed.ClientId);
        Assert.Equal(CredentialType, parsed.CredentialType);
        Assert.Equal(ResponseUri, parsed.ResponseUri);

        using (var requestDocument = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(request)))
        {
            var root = requestDocument.RootElement;
            Assert.Equal("vp_token", root.GetProperty("response_type").GetString());
            Assert.Equal("direct_post", root.GetProperty("response_mode").GetString());
            Assert.Equal("jwt_vc_json", root.GetProperty("dcql_query")
                .GetProperty("credentials")[0].GetProperty("format").GetString());
            Assert.Equal("EdDSA", root.GetProperty("client_metadata")
                .GetProperty("vp_formats_supported").GetProperty("jwt_vc_json")
                .GetProperty("alg_values")[0].GetString());
            Assert.Equal("VerifiableCredential", root.GetProperty("dcql_query")
                .GetProperty("credentials")[0].GetProperty("meta")
                .GetProperty("type_values")[0][0].GetString());
            Assert.Equal(CredentialType, root.GetProperty("dcql_query")
                .GetProperty("credentials")[0].GetProperty("meta")
                .GetProperty("type_values")[0][1].GetString());
        }

        string credential = Credential();
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext,
            credential, _holder.Did, _holder.Seed, _clock);
        string formToken = WebUtility.UrlDecode(form.Split('&')[0]["vp_token=".Length..]);
        using (var responseDocument = JsonDocument.Parse(formToken))
        {
            var vp = responseDocument.RootElement.GetProperty("jwt_vc_json_credential");
            Assert.Equal(1, vp.GetArrayLength());
            using var jwtDocument = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(vp[0].GetString()!));
            Assert.Equal(Audience, jwtDocument.RootElement.GetProperty("aud").GetString());
            Assert.Equal(challenge.Nonce, jwtDocument.RootElement.GetProperty("nonce").GetString());
            Assert.Equal(credential, jwtDocument.RootElement.GetProperty("vp")
                .GetProperty("verifiableCredential")[0].GetString());
        }

        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant, Audience,
                challenge.Nonce, CredentialType, SubjectContext, store, _clock, out var claims));
        Assert.Equal(_holder.Did, claims.GetProperty("id").GetString());
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant, Audience,
                challenge.Nonce, CredentialType, SubjectContext, store, _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void WalletPinsVerifierSignatureCallbackCredentialTypeAndSubjectVocabulary()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string request = Request(challenge);

        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            request, _other.Did, ResponseUri, CredentialType, SubjectContext, _clock, out _));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            request, _verifier.Did, new Uri("https://attacker.example/collect"),
            CredentialType, SubjectContext, _clock, out _));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            request, _verifier.Did, ResponseUri, "AdminCredential", SubjectContext, _clock, out _));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            request, _verifier.Did, ResponseUri, CredentialType,
            new Uri("https://attacker.example/context"), _clock, out _));

        string changed = Ed25519JwtSigner.ExtractPayload(request).Replace(
            "jwt_vc_json", "dc+sd-jwt", StringComparison.Ordinal);
        string otherFormat = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(request), changed, _verifier.Seed);
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            otherFormat, _verifier.Did, ResponseUri, CredentialType, SubjectContext, _clock, out _));

        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _other.Seed, ResponseUri, CredentialType, SubjectContext, _clock));
        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, new Uri("http://verifier.example/response"),
            CredentialType, SubjectContext, _clock));
        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _other.Did, ResponseUri, CredentialType, SubjectContext,
            Credential(), _holder.Did, _holder.Seed, _clock));
    }

    [Fact]
    public void ForgedCredentialAndWrongHolderSeedNeverBecomeIssuerOrHolderProof()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string request = Request(challenge);
        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext,
            Credential(_other.Seed), _holder.Did, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext,
            Credential(), _holder.Did, _other.Seed, _clock));
        Assert.Throws<ArgumentException>(() => OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(\n            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext,\n            Credential(), _holder.Did, _other.Seed, _clock));
    }

    [Fact]
    public void StateTenantSignatureAndExpiredRequestFailuresDoNotReleaseClaims()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = Request(challenge);
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _verifier.Did, ResponseUri, CredentialType, SubjectContext,
            Credential(), _holder.Did, _holder.Seed, _clock);

        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, Guid.NewGuid(),
                Audience, challenge.Nonce, CredentialType, SubjectContext, store, _clock, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form + "&state=second",
                tenant, Audience, challenge.Nonce, CredentialType, SubjectContext, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form,
                tenant, Audience, challenge.Nonce, "AdminCredential", SubjectContext, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant,
                Audience, challenge.Nonce, CredentialType, SubjectContext, store, _clock, out _));

        var newChallenge = store.Issue(tenant, Audience, _issuer.Did, TimeSpan.FromSeconds(1));
        string expiringRequest = Request(newChallenge);
        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            expiringRequest, _verifier.Did, ResponseUri, CredentialType, SubjectContext, _clock, out _));
    }

    private string Request(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, ResponseUri, CredentialType, SubjectContext, _clock);

    private string Credential(byte[]? seed = null)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType,
            SubjectContext, doc.RootElement, seed ?? _issuer.Seed,
            _clock.GetUtcNow().AddSeconds(-5), _clock.GetUtcNow().AddMinutes(5));
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed class FakeClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _time = start;
        public override DateTimeOffset GetUtcNow() => _time;
        public void Advance(TimeSpan elapsed) => _time = _time.Add(elapsed);
    }
}
