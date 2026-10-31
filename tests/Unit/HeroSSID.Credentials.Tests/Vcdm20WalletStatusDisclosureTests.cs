using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20WalletStatusDisclosureTests
{
    private const string Audience = "https://verifier.example/present-vc2";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 31, 2, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _attacker = NewIdentity();

    [Fact]
    public void AuthenticNotListedStatusAllowsPreviewThenHolderSigningAndOneUseVerification()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did);
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);

        Assert.True(Prepare(request, credential, snapshot, out var preview));
        Assert.NotNull(preview);
        Assert.Equal(_holder.Did, preview!.Disclosure.VerifiedSubject.GetProperty("id").GetString());
        Assert.Equal("member", preview.Disclosure.VerifiedSubject.GetProperty("membership").GetString());
        Assert.Equal(64, preview.SnapshotSha256.Length);

        // Only the integrating Wallet may obtain actual full-disclosure consent.
        string proof = Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
            preview, request, credential, snapshot, _holder.Seed, _clock);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentation(proof, snapshot, tenant,
                Audience, challenge.Nonce, CredentialType, Context, challenges,
                _clock, out var accepted));
        Assert.Equal("member", accepted.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentation(proof, snapshot, tenant,
                Audience, challenge.Nonce, CredentialType, Context, challenges,
                _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void RevokedOrForgedSnapshotFailsClosedBeforeExposingClaimsOrHolderKey()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string revoked = SignSnapshot([credential]);
        Assert.False(Prepare(request, credential, revoked, out var denied));
        Assert.Null(denied);

        string valid = SignSnapshot([]);
        string forged = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(valid),
            Ed25519JwtSigner.ExtractPayload(valid), _attacker.Seed);
        Assert.False(Prepare(request, credential, forged, out denied));
        Assert.Null(denied);
        Assert.False(Prepare(request, credential, string.Empty, out denied));
        Assert.Null(denied);
    }

    [Fact]
    public void SignedStatusMustRemainByteIdenticalAndFreshBetweenPreviewAndSigning()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);
        Assert.True(Prepare(request, credential, snapshot, out var preview));
        Assert.NotNull(preview);

        _clock.Advance(TimeSpan.FromSeconds(1));
        string replacement = SignSnapshot([]);
        Assert.NotEqual(snapshot, replacement);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, request, credential, replacement, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, request, credential, SignSnapshot([credential]), _holder.Seed, _clock));

        _clock.Advance(TimeSpan.FromSeconds(60));
        Assert.False(Prepare(request, credential, snapshot, out var denied));
        Assert.Null(denied);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, request, credential, snapshot, _holder.Seed, _clock));
    }

    [Fact]
    public void CredentialRequestAndHolderKeySubstitutionCannotReuseStatusPreview()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);
        Assert.True(Prepare(request, credential, snapshot, out var preview));
        Assert.NotNull(preview);

        string otherCredential = IssueCredential("administrator");
        string otherRequest = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, request, otherCredential, snapshot, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, otherRequest, credential, snapshot, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreview(
                preview!, request, credential, snapshot, _attacker.Seed, _clock));
    }

    [Fact]
    public void StrictStatusAwareWalletRefusesAuthenticLegacyRequestBeforeDisclosure()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);

        Assert.True(Prepare(request, credential, snapshot, out var legacyPreview));
        Assert.NotNull(legacyPreview);

        Assert.False(Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
            request, _verifier.Did, Audience, CredentialType, Context,
            _issuer.Did, credential, _holder.Did, snapshot, _clock,
            out var strictPreview));
        Assert.Null(strictPreview);
    }

    [Fact]
    public void StrictStatusAwareWalletAuthenticatesSignedTypeContextAndStatusBeforeOneUseHolderProof()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);

        Assert.True(Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
            request, _verifier.Did, Audience, CredentialType, Context,
            _issuer.Did, credential, _holder.Did, snapshot, _clock,
            out var strictPreview));
        Assert.NotNull(strictPreview);
        Assert.Equal("member", strictPreview!.Disclosure.VerifiedSubject.GetProperty("membership").GetString());

        string proof = Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreviewRequiringSignedPolicy(
            strictPreview, request, credential, snapshot, _holder.Seed, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentation(proof, snapshot, tenant,
                Audience, challenge.Nonce, CredentialType, Context, challenges,
                _clock, out var claims));
        Assert.Equal("member", claims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentation(proof, snapshot, tenant,
                Audience, challenge.Nonce, CredentialType, Context, challenges,
                _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void StrictStatusAwareSigningRefusesLegacyPreviewEvenWhenStatusAndIssuerAreAuthentic()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);
        Assert.True(Prepare(request, credential, snapshot, out var legacyPreview));
        Assert.NotNull(legacyPreview);

        Assert.Throws<ArgumentException>(() =>
            Vcdm20WalletDisclosure.CreateHolderPresentationAfterStatusPreviewRequiringSignedPolicy(
                legacyPreview!, request, credential, snapshot, _holder.Seed, _clock));
    }

    [Fact]
    public void StrictStatusAwareWalletRejectsRevocationAndMismatchedVerifierPolicy()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        string snapshot = SignSnapshot([]);

        Assert.False(Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
            request, _verifier.Did, Audience, "AdministratorCredential", Context,
            _issuer.Did, credential, _holder.Did, snapshot, _clock, out var denied));
        Assert.Null(denied);
        Assert.False(Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
            request, _verifier.Did, Audience, CredentialType,
            new Uri("https://issuer.example/contexts/admin/v1"),
            _issuer.Did, credential, _holder.Did, snapshot, _clock, out denied));
        Assert.Null(denied);
        Assert.False(Vcdm20WalletDisclosure.TryPrepareWithStatusRequiringSignedPolicy(
            request, _verifier.Did, Audience, CredentialType, Context,
            _issuer.Did, credential, _holder.Did, SignSnapshot([credential]),
            _clock, out denied));
        Assert.Null(denied);
    }

    private bool Prepare(string request, string credential, string snapshot,
        out Vcdm20WalletStatusDisclosurePreview? preview) =>
        Vcdm20WalletDisclosure.TryPrepareWithStatus(request, _verifier.Did, Audience,
            CredentialType, Context, _issuer.Did, credential, _holder.Did,
            snapshot, _clock, out preview);

    private string SignRequest(PresentationChallenge challenge) =>
        OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);

    private string SignSnapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(
            _issuer.Did, revoked, _issuer.Seed, _clock.GetUtcNow(), _clock);

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
