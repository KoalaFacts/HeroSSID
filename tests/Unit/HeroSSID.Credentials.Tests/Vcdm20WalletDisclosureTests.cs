using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20WalletDisclosureTests
{
    private const string Audience = "https://verifier.example/present-vc2";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 31, 1, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _attacker = NewIdentity();

    [Fact]
    public void AuthenticVc2ClaimsArePreviewedWithoutHolderKeyAndThenSignedOnce()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did);
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");

        Assert.True(Prepare(request, credential, _verifier.Did, Audience, CredentialType,
            Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);
        Assert.Equal(_verifier.Did, preview!.VerifierDid);
        Assert.Equal(Audience, preview.VerifierAudience);
        Assert.Equal(_issuer.Did, preview.TrustedIssuerDid);
        Assert.Equal(_holder.Did, preview.HolderDid);
        Assert.Equal(CredentialType, preview.CredentialType);
        Assert.Equal(Context, preview.SubjectContextUri);
        Assert.Equal(challenge.ExpiresAt, preview.RequestExpiresAt);
        Assert.Equal(_holder.Did, preview.VerifiedSubject.GetProperty("id").GetString());
        Assert.Equal("member", preview.VerifiedSubject.GetProperty("membership").GetString());
        Assert.Equal(64, preview.RequestSha256.Length);
        Assert.Equal(64, preview.CredentialSha256.Length);

        // Preview never signs or spends the challenge. A real wallet UI must
        // independently obtain informed consent here before using the seed.
        Assert.True(Prepare(request, credential, _verifier.Did, Audience, CredentialType,
            Context, _issuer.Did, _holder.Did, out var secondPreview));
        Assert.Equal(preview.RequestSha256, secondPreview!.RequestSha256);

        string presentation = Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
            preview, request, credential, _holder.Seed, _clock);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                CredentialType, Context, challenges, _clock, out var verifiedClaims));
        Assert.Equal("member", verifiedClaims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                CredentialType, Context, challenges, _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void PreviewRejectsUntrustedVerifierIssuerHolderVocabularyAndForgedSignatures()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");

        AssertDenied(request, credential, _attacker.Did, Audience,
            CredentialType, Context, _issuer.Did, _holder.Did);
        AssertDenied(request, credential, _verifier.Did, "https://evil.example/present",
            CredentialType, Context, _issuer.Did, _holder.Did);
        AssertDenied(request, credential, _verifier.Did, Audience,
            "AdminCredential", Context, _issuer.Did, _holder.Did);
        AssertDenied(request, credential, _verifier.Did, Audience,
            CredentialType, new Uri("https://evil.example/context"), _issuer.Did, _holder.Did);
        AssertDenied(request, credential, _verifier.Did, Audience,
            CredentialType, Context, _attacker.Did, _holder.Did);
        AssertDenied(request, credential, _verifier.Did, Audience,
            CredentialType, Context, _issuer.Did, _attacker.Did);

        string forgedCredential = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(credential),
            Ed25519JwtSigner.ExtractPayload(credential), _attacker.Seed);
        AssertDenied(request, forgedCredential, _verifier.Did, Audience,
            CredentialType, Context, _issuer.Did, _holder.Did);

        string forgedRequest = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(request),
            Ed25519JwtSigner.ExtractPayload(request), _attacker.Seed);
        AssertDenied(forgedRequest, credential, _verifier.Did, Audience,
            CredentialType, Context, _issuer.Did, _holder.Did);
    }

    [Fact]
    public void AfterPreviewRefusesAuthenticButSubstitutedRequestCredentialAndSubject()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did);
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        Assert.True(Prepare(request, credential, _verifier.Did, Audience, CredentialType,
            Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);

        string replacementCredential = IssueCredential("administrator");
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
                preview!, request, replacementCredential, _holder.Seed, _clock));

        string replacementRequest = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
                preview!, replacementRequest, credential, _holder.Seed, _clock));

        using var forgedSubject = JsonDocument.Parse("{\"id\":\"did:key:zFake\",\"role\":\"admin\"}");
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
                preview! with { VerifiedSubject = forgedSubject.RootElement.Clone() },
                request, credential, _holder.Seed, _clock));

        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
                preview!, request, credential, _attacker.Seed, _clock));

        // Invalid attempts cannot consume the original one-use challenge.
        string proof = Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
            preview!, request, credential, _holder.Seed, _clock);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(proof, tenant, Audience, challenge.Nonce,
                CredentialType, Context, challenges, _clock, out _));
    }

    [Fact]
    public void ExpiredRequestFailsBothBeforeAndAfterThePreview()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did, TimeSpan.FromSeconds(30));
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        Assert.True(Prepare(request, credential, _verifier.Did, Audience, CredentialType,
            Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);

        _clock.Advance(TimeSpan.FromMinutes(4));
        AssertDenied(request, credential, _verifier.Did, Audience,
            CredentialType, Context, _issuer.Did, _holder.Did);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
                preview!, request, credential, _holder.Seed, _clock));
    }

    [Fact]
    public void VerifierSignsVc2CredentialTypeAndExactContextBeforeWalletDisclosure()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(request));
        Assert.Equal(CredentialType,
            document.RootElement.GetProperty("credentialType").GetString());
        Assert.Equal(Context.AbsoluteUri,
            document.RootElement.GetProperty("subjectContextUri").GetString());

        string credential = IssueCredential("member");
        Assert.True(Prepare(request, credential, _verifier.Did, Audience, CredentialType,
            Context, _issuer.Did, _holder.Did, out var preview));
        Assert.NotNull(preview);
        string presentation = Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
            preview!, request, credential, _holder.Seed, _clock);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                CredentialType, Context, store, _clock, out var claims));
        Assert.Equal("member", claims.GetProperty("membership").GetString());
    }

    [Fact]
    public void BoundVerifierPolicyRefusesSubstitutedAuthenticCredentialType()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        string otherCredential = IssueCredentialWithPolicy(
            "AdministratorCredential", Context, "administrator");
        Assert.False(Prepare(request, otherCredential, _verifier.Did, Audience,
            "AdministratorCredential", Context, _issuer.Did, _holder.Did, out var preview));
        Assert.Null(preview);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
                otherCredential, "AdministratorCredential", Context,
                _holder.Did, _holder.Seed, _clock));
    }

    [Fact]
    public void BoundVerifierPolicyRefusesSubstitutedAuthenticSubjectVocabulary()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        var alternateContext = new Uri("https://issuer.example/contexts/admin/v1");
        string otherCredential = IssueCredentialWithPolicy(
            CredentialType, alternateContext, "administrator");
        Assert.False(Prepare(request, otherCredential, _verifier.Did, Audience,
            CredentialType, alternateContext, _issuer.Did, _holder.Did, out var preview));
        Assert.Null(preview);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
                otherCredential, CredentialType, alternateContext,
                _holder.Did, _holder.Seed, _clock));
    }

    private string IssueCredentialWithPolicy(string type, Uri vocabulary, string membership)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership }));
        return Vcdm20JoseCredential.Create(
            _issuer.Did, _holder.Did, type, vocabulary,
            subject.RootElement, _issuer.Seed,
            _clock.GetUtcNow().AddMinutes(-1), _clock.GetUtcNow().AddMinutes(5));
    }

    private bool Prepare(string request, string credential, string verifierDid,
        string audience, string type, Uri context, string issuerDid, string holderDid,
        out Vcdm20WalletDisclosurePreview? preview) =>
        Vcdm20WalletDisclosure.TryPrepare(request, verifierDid, audience, type,
            context, issuerDid, credential, holderDid, _clock, out preview);

    private void AssertDenied(string request, string credential, string verifierDid,
        string audience, string type, Uri context, string issuerDid, string holderDid)
    {
        Assert.False(Prepare(request, credential, verifierDid, audience, type,
            context, issuerDid, holderDid, out var preview));
        Assert.Null(preview);
    }

    private string SignRequest(PresentationChallenge challenge) =>
        OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);

    private string IssueCredential(string membership)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership }));
        return Vcdm20JoseCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Context,
            subject.RootElement, _issuer.Seed,
            _clock.GetUtcNow().AddMinutes(-1), _clock.GetUtcNow().AddMinutes(5));
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
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
