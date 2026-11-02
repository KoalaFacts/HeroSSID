using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20WalletIncidentDisclosureTests
{
    private const string Audience = "https://verifier.example/vc2-present";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 11, 3, 0, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _attacker = NewIdentity();

    [Fact]
    public void FreshPostIncidentIssuerStatusPermitsHolderBoundProofAndOneTimeVerification()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did) with
        {
            CredentialType = CredentialType,
            SubjectContextUri = Context
        };
        string request = SignRequest(challenge);
        string credential = IssueCredential();
        string before = SignSnapshot([]);
        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset minimum = _clock.GetUtcNow();
        string after = SignSnapshot([]);
        Assert.NotEqual(before, after);

        Assert.True(Prepare(request, credential, after, minimum, out var preview));
        Assert.NotNull(preview);
        Assert.Equal(minimum, preview!.MinimumObservedAt);
        Assert.Equal("member", preview.Status.Disclosure.VerifiedSubject
            .GetProperty("membership").GetString());

        // Integrating Wallet displays all subject claims and obtains real consent here.
        string proof = Sign(preview, request, credential, after, minimum);
        string pin = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(request)));
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                proof, request, pin, _verifier.Did, after, tenant,
                Audience, challenge.Nonce, CredentialType, Context,
                challenges, _clock, out var verified));
        Assert.Equal("member", verified.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                proof, request, pin, _verifier.Did, after, tenant,
                Audience, challenge.Nonce, CredentialType, Context,
                challenges, _clock, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void AuthenticStillFreshPreIncidentStatusNeverReleasesSubject()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(WithPolicy(store.Issue(Guid.NewGuid(), Audience, _issuer.Did)));
        string credential = IssueCredential();
        string earlier = SignSnapshot([]);
        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset minimum = _clock.GetUtcNow();

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(
                earlier, credential, _issuer.Did, _clock.GetUtcNow()));
        Assert.False(Prepare(request, credential, earlier, minimum, out var rejected));
        Assert.Null(rejected);
        Assert.False(Prepare(request, credential, earlier,
            minimum.AddSeconds(30), out rejected));
        Assert.Null(rejected);
    }

    [Fact]
    public void IncidentCutoffCannotBeDowngradedBetweenConsentAndHolderSigning()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(WithPolicy(store.Issue(Guid.NewGuid(), Audience, _issuer.Did)));
        string credential = IssueCredential();
        string snapshot = SignSnapshot([]);
        DateTimeOffset minimum = _clock.GetUtcNow();
        Assert.True(Prepare(request, credential, snapshot, minimum, out var preview));
        Assert.NotNull(preview);

        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset incident = _clock.GetUtcNow();
        Assert.Throws<ArgumentException>(() =>
            Sign(preview!, request, credential, snapshot, incident));
        Assert.Throws<ArgumentException>(() =>
            Sign(preview! with { MinimumObservedAt = incident },
                request, credential, snapshot, incident));
        Assert.Throws<ArgumentException>(() =>
            Sign(preview!, request, credential, snapshot, minimum, _attacker.Seed));
        string later = SignSnapshot([]);
        Assert.Throws<ArgumentException>(() =>
            Sign(preview!, request, credential, later, minimum));

        Assert.True(Prepare(request, credential, later, incident, out var fresh));
        Assert.NotNull(fresh);
        Assert.False(Prepare(request, credential, SignSnapshot([credential]), incident,
            out var revoked));
        Assert.Null(revoked);
    }

    [Fact]
    public void FractionalSecondIncidentCutoffRequiresLaterIssuerObservation()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(WithPolicy(store.Issue(Guid.NewGuid(), Audience, _issuer.Did)));
        string credential = IssueCredential();
        string snapshot = SignSnapshot([]);
        _clock.Advance(TimeSpan.FromMilliseconds(100));
        DateTimeOffset cutoff = _clock.GetUtcNow();

        Assert.False(Prepare(request, credential, snapshot, cutoff, out var denied));
        Assert.Null(denied);
        _clock.Advance(TimeSpan.FromMilliseconds(900));
        string nextSecond = SignSnapshot([]);
        Assert.True(Prepare(request, credential, nextSecond, cutoff, out var accepted));
        Assert.NotNull(accepted);
    }

    private bool Prepare(string request, string credential, string status,
        DateTimeOffset minimum, out Vcdm20WalletIncidentDisclosurePreview? preview) =>
        Vcdm20WalletIncidentDisclosure.TryPrepare(
            request, _verifier.Did, Audience, CredentialType, Context,
            _issuer.Did, credential, _holder.Did, status, minimum,
            _clock, out preview);

    private string Sign(Vcdm20WalletIncidentDisclosurePreview preview,
        string request, string credential, string status, DateTimeOffset minimum,
        byte[]? seed = null) =>
        Vcdm20WalletIncidentDisclosure.CreateHolderBoundPresentationAfterPreview(
            preview, request, credential, status, minimum, seed ?? _holder.Seed, _clock);

    private string SignRequest(PresentationChallenge challenge) =>
        OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);

    private static PresentationChallenge WithPolicy(PresentationChallenge challenge) =>
        challenge with { CredentialType = CredentialType, SubjectContextUri = Context };

    private string SignSnapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(
            _issuer.Did, revoked, _issuer.Seed, _clock.GetUtcNow(), _clock);

    private string IssueCredential()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "member" }));
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

    private sealed class TestClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan amount) => _now = _now.Add(amount);
    }
}
