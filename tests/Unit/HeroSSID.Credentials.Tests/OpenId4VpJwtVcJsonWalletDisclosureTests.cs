using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpJwtVcJsonWalletDisclosureTests
{
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Callback = new("https://verifier.example/direct-post");
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 31, 0, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();

    private string Audience => "decentralized_identifier:" + _verifier.Did;

    [Fact]
    public void PreviewShowsTheOriginalAuthenticatedIssuerClaimsWithoutSigningOrSpendingChallenge()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = SignRequest(challenge);
        string credential = IssueCredential("active");

        Assert.True(Prepare(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);
        Assert.Equal(_verifier.Did, preview!.VerifierDid);
        Assert.Equal(Callback, preview.ResponseUri);
        Assert.Equal(_issuer.Did, preview.TrustedIssuerDid);
        Assert.Equal(_holder.Did, preview.HolderDid);
        Assert.Equal(CredentialType, preview.CredentialType);
        Assert.Equal(Context, preview.SubjectContextUri);
        Assert.Equal(challenge.ExpiresAt, preview.RequestExpiresAt);
        Assert.Equal(_holder.Did, preview.VerifiedSubject.GetProperty("id").GetString());
        Assert.Equal("active", preview.VerifiedSubject.GetProperty("membership").GetString());
        Assert.Equal(64, preview.RequestSha256.Length);
        Assert.Equal(64, preview.CredentialSha256.Length);

        // Merely showing a verified preview cannot consume or sign the holder's challenge.
        Assert.True(Prepare(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did, out var secondPreview));
        Assert.NotNull(secondPreview);
        Assert.Equal(preview.RequestSha256, secondPreview!.RequestSha256);

        // The caller must separately obtain real full-disclosure consent here.
        string form = OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
            preview, signedRequest, credential, _holder.Seed, _clock);
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant, Audience,
                challenge.Nonce, CredentialType, Context, challenges, _clock, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant, Audience,
                challenge.Nonce, CredentialType, Context, challenges, _clock, out _));
    }

    [Fact]
    public void PreviewRejectsUntrustedVerifierIssuerHolderAndVocabularyWithoutRevealingSubject()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string signedRequest = SignRequest(challenge);
        string credential = IssueCredential("member-only");

        AssertDenied(signedRequest, credential, _other.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did);
        AssertDenied(signedRequest, credential, _verifier.Did, new Uri("https://evil.example/collect"),
            CredentialType, Context, _issuer.Did, _holder.Did);
        AssertDenied(signedRequest, credential, _verifier.Did, Callback,
            "https://evil.example/credentials#Admin", Context, _issuer.Did, _holder.Did);
        AssertDenied(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, new Uri("https://evil.example/context"), _issuer.Did, _holder.Did);
        AssertDenied(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _other.Did, _holder.Did);
        AssertDenied(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _other.Did);

        string forgedCredential = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(credential),
            Ed25519JwtSigner.ExtractPayload(credential), _other.Seed);
        AssertDenied(signedRequest, forgedCredential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did);
    }

    [Fact]
    public void SigningAfterPreviewCannotSubstituteAnotherAuthenticCredentialOrSignedRequest()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        Guid tenant = Guid.NewGuid();
        var original = challenges.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = SignRequest(original);
        string credential = IssueCredential("active");
        Assert.True(Prepare(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);

        string otherCredential = IssueCredential("admin");
        Assert.Throws<ArgumentException>(() =>
            OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
                preview!, signedRequest, otherCredential, _holder.Seed, _clock));

        var newChallenge = challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string otherRequest = SignRequest(newChallenge);
        Assert.Throws<ArgumentException>(() =>
            OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
                preview!, otherRequest, credential, _holder.Seed, _clock));

        Assert.Throws<ArgumentException>(() =>
            OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
                preview!, signedRequest, credential, _other.Seed, _clock));

        // Failed signing never consumes the original verifier challenge.
        string form = OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
            preview!, signedRequest, credential, _holder.Seed, _clock);
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckResponseForm(form, tenant,
                Audience, original.Nonce, CredentialType, Context, challenges, _clock, out _));
    }

    [Fact]
    public void ExpiredRequestAndCredentialFailBeforePreviewOrAfterFormerPreview()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did, TimeSpan.FromSeconds(30));
        string signedRequest = SignRequest(challenge);
        string credential = IssueCredential("active");
        Assert.True(Prepare(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did, out var preview));

        _clock.Advance(TimeSpan.FromMinutes(6));
        AssertDenied(signedRequest, credential, _verifier.Did, Callback,
            CredentialType, Context, _issuer.Did, _holder.Did);
        Assert.Throws<ArgumentException>(() =>
            OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
                preview!, signedRequest, credential, _holder.Seed, _clock));
    }

    private bool Prepare(string signedRequest, string credential, string verifierDid,
        Uri callback, string credentialType, Uri context, string issuerDid,
        string holderDid, out JwtVcJsonWalletDisclosurePreview? preview) =>
        OpenId4VpJwtVcJsonWalletDisclosure.TryPrepare(
            signedRequest, verifierDid, callback, credentialType,
            context, issuerDid, credential, holderDid, _clock, out preview);

    private void AssertDenied(string signedRequest, string credential, string verifierDid,
        Uri callback, string credentialType, Uri context, string issuerDid, string holderDid)
    {
        Assert.False(Prepare(signedRequest, credential, verifierDid, callback,
            credentialType, context, issuerDid, holderDid, out var preview));
        Assert.Null(preview);
    }

    private string SignRequest(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(challenge, _verifier.Did,
            _verifier.Seed, Callback, CredentialType, Context, _clock);

    private string IssueCredential(string membership)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _holder.Did,
            membership
        }));
        return JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
            CredentialType, Context, subject.RootElement, _issuer.Seed,
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
        public void Advance(TimeSpan duration) => _time = _time.Add(duration);
    }
}
