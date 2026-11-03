using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonWalletIncidentDisclosureTests
{
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Callback = new("https://verifier.example/direct-post");
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 11, 3, 0, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();

    private string Audience => "decentralized_identifier:" + _verifier.Did;

    [Fact]
    public void GenuinePostIncidentStatusAllowsHolderBoundProofAndAtomicReplayRejection()
    {
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        var challenge = challenges.Issue(tenant, Audience, _issuer.Did);
        string request = SignRequest(challenge);
        string credential = IssueCredential("member");
        DateTimeOffset cutoff = _clock.GetUtcNow();
        string status = SignSnapshot([]);

        Assert.True(Prepare(request, credential, status, cutoff, out var preview));
        Assert.NotNull(preview);
        Assert.Equal(cutoff, preview!.MinimumObservedAt);
        Assert.Equal("member", preview.Status.Disclosure.VerifiedSubject
            .GetProperty("membership").GetString());

        // Only the integrating Wallet can show this full disclosure and obtain consent.
        string form = Sign(preview, request, credential, status, cutoff);
        string originalPin = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(request)));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseFormWithObservationCutoff(
                form, status, request, originalPin, _verifier.Did, Callback,
                tenant, Audience, challenge.Nonce, CredentialType, Context,
                challenges, _clock, cutoff, out var claims));
        Assert.Equal("member", claims.GetProperty("membership").GetString());
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseFormWithObservationCutoff(
                form, status, request, originalPin, _verifier.Did, Callback,
                tenant, Audience, challenge.Nonce, CredentialType, Context,
                challenges, _clock, cutoff, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void AuthenticFreshButPreIncidentStatusCannotRevealAnyClaims()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string earlier = SignSnapshot([]);
        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset cutoff = _clock.GetUtcNow();

        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(earlier, credential,
                _issuer.Did, _clock.GetUtcNow()));
        Assert.False(Prepare(request, credential, earlier, cutoff, out var preview));
        Assert.Null(preview);
        Assert.False(Prepare(request, credential, string.Empty, cutoff, out preview));
        Assert.Null(preview);
    }

    [Fact]
    public void ChangedIncidentPolicyRequiresNewPreviewAndActualHolderKey()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        DateTimeOffset previousCutoff = _clock.GetUtcNow();
        string previousStatus = SignSnapshot([]);
        Assert.True(Prepare(request, credential, previousStatus, previousCutoff,
            out var preview));
        Assert.NotNull(preview);

        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset newCutoff = _clock.GetUtcNow();
        Assert.Throws<ArgumentException>(() =>
            Sign(preview!, request, credential, previousStatus, newCutoff));
        Assert.Throws<ArgumentException>(() =>
            Sign(preview! with { MinimumObservedAt = newCutoff },
                request, credential, previousStatus, newCutoff));

        string currentStatus = SignSnapshot([]);
        Assert.Throws<ArgumentException>(() =>
            Sign(preview!, request, credential, currentStatus, previousCutoff));
        Assert.True(Prepare(request, credential, currentStatus, newCutoff,
            out var newPreview));
        Assert.NotNull(newPreview);
        Assert.Throws<ArgumentException>(() =>
            Sign(newPreview!, request, credential, currentStatus, newCutoff, _other.Seed));
        Assert.Throws<ArgumentException>(() =>
            Sign(newPreview!, request, IssueCredential("admin"),
                currentStatus, newCutoff));

        string acceptedForm = Sign(newPreview!, request, credential, currentStatus, newCutoff);
        Assert.StartsWith("vp_token=", acceptedForm, StringComparison.Ordinal);
    }

    [Fact]
    public void FractionalCutoffFutureCutoffAndRevokedIssuerStatusFailClosed()
    {
        var challenges = new InMemoryPresentationChallengeStore(_clock);
        string request = SignRequest(challenges.Issue(Guid.NewGuid(), Audience, _issuer.Did));
        string credential = IssueCredential("member");
        string status = SignSnapshot([]);
        _clock.Advance(TimeSpan.FromMilliseconds(500));
        DateTimeOffset fractionalCutoff = _clock.GetUtcNow();

        Assert.False(Prepare(request, credential, status, fractionalCutoff, out var denied));
        Assert.Null(denied);
        Assert.False(Prepare(request, credential, status,
            fractionalCutoff.AddMinutes(1), out denied));
        Assert.Null(denied);
        Assert.False(Prepare(request, credential, status,
            DateTimeOffset.UnixEpoch.AddSeconds(-1), out denied));
        Assert.Null(denied);

        _clock.Advance(TimeSpan.FromMilliseconds(500));
        string nextSecond = SignSnapshot([]);
        Assert.True(Prepare(request, credential, nextSecond, fractionalCutoff,
            out var accepted));
        Assert.NotNull(accepted);
        Assert.False(Prepare(request, credential, SignSnapshot([credential]),
            fractionalCutoff, out denied));
        Assert.Null(denied);
    }

    private bool Prepare(string request, string credential, string status,
        DateTimeOffset cutoff, out JwtVcJsonWalletIncidentDisclosurePreview? preview) =>
        JwtVcJsonWalletIncidentDisclosure.TryPrepare(
            request, _verifier.Did, Callback, CredentialType, Context,
            _issuer.Did, credential, _holder.Did, status, cutoff, _clock, out preview);

    private string Sign(JwtVcJsonWalletIncidentDisclosurePreview preview,
        string request, string credential, string status, DateTimeOffset cutoff,
        byte[]? seed = null) =>
        JwtVcJsonWalletIncidentDisclosure.CreateHolderBoundResponseFormAfterPreview(
            preview, request, credential, status, cutoff, seed ?? _holder.Seed, _clock);

    private string SignRequest(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, Callback,
            CredentialType, Context, _clock);

    private string SignSnapshot(IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, revoked, _issuer.Seed, _clock.GetUtcNow(), _clock);

    private string IssueCredential(string membership)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership }));
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
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
