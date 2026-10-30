using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonDirectPostRevocationTests
{
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Callback = new("https://verifier.example/oid4vp/response");
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 30, 10, 0, 0, TimeSpan.Zero));
    private readonly Identity _issuer = NewIdentity();
    private readonly Identity _holder = NewIdentity();
    private readonly Identity _verifier = NewIdentity();
    private readonly Identity _foreign = NewIdentity();
    private string Audience => "decentralized_identifier:" + _verifier.Did;

    [Fact]
    public void RevokedExactCredentialDoesNotReleaseClaimsAndSpendsChallenge()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string credential = Issue("revoked");
        string form = Form(challenge, credential);
        string snapshot = Snapshot([credential]);

        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            Check(form, snapshot, tenant, challenge.Nonce, store, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(form, snapshot, tenant, challenge.Nonce, store, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void FreshSignedIssuerSnapshotBindsToOriginalCredentialInsidePresentation()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string presented = Issue("active");
        string anotherCredential = Issue("revoked");
        string snapshot = Snapshot([anotherCredential]);

        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            IssuerRevocationSnapshot.Check(snapshot, anotherCredential,
                _issuer.Did, _issuer.PublicKey, _clock.GetUtcNow()));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            Check(Form(challenge, presented), snapshot, tenant, challenge.Nonce, store, out var claims));
        Assert.Equal(_holder.Did, claims.GetProperty("id").GetString());
        Assert.Equal("active", claims.GetProperty("membership").GetString());
    }

    [Fact]
    public void ForeignIssuerStatusCannotBeSubstitutedForTrustedIssuer()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string credential = Issue("active");
        string foreignStatus = IssuerRevocationSnapshot.Create(
            _foreign.Did, [], _foreign.Seed, _foreign.PublicKey, _clock.GetUtcNow());

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(Form(challenge, credential), foreignStatus, tenant, challenge.Nonce, store, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    [Fact]
    public void InvalidStatusSignatureAndExpiredSnapshotNeverDiscloseClaims()
    {
        string credential = Issue("active");
        string snapshot = Snapshot([]);
        var parts = snapshot.Split('.');
        parts[1] = Base64UrlEncoder.Encode("{}");
        string forgedStatus = string.Join('.', parts);

        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(Form(challenge, credential), forgedStatus, tenant, challenge.Nonce, store, out var forgedClaims));
        Assert.Equal(JsonValueKind.Undefined, forgedClaims.ValueKind);

        var later = store.Issue(tenant, Audience, _issuer.Did);
        string form = Form(later, credential);
        _clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(form, snapshot, tenant, later.Nonce, store, out var staleClaims));
        Assert.Equal(JsonValueKind.Undefined, staleClaims.ValueKind);
    }

    [Fact]
    public void ForeignTenantIsDeniedWithoutSpendingTheRealVerifierChallenge()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string form = Form(challenge, Issue("active"));
        string snapshot = Snapshot([]);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(form, snapshot, Guid.NewGuid(), challenge.Nonce, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            Check(form, snapshot, tenant, challenge.Nonce, store, out var accepted));
        Assert.Equal(_holder.Did, accepted.GetProperty("id").GetString());
    }

    private RevocationSnapshotCheckResult Check(string form, string snapshot, Guid tenant,
        string nonce, IPresentationChallengeStore store, out JsonElement claims) =>
        JwtVcJsonDirectPostRevocation.CheckResponseForm(form, snapshot, tenant, Audience,
            nonce, CredentialType, Context, store, _clock, out claims);

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        IssuerRevocationSnapshot.Create(_issuer.Did, revoked, _issuer.Seed,
            _issuer.PublicKey, _clock.GetUtcNow());

    private string Form(PresentationChallenge challenge, string credential)
    {
        string request = OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, Callback, CredentialType, Context, _clock);
        return OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            request, _verifier.Did, Callback, CredentialType, Context,
            credential, _holder.Did, _holder.Seed, _clock);
    }

    private string Issue(string membership)
    {
        var subject = JsonSerializer.SerializeToElement(new { id = _holder.Did, membership });
        return JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType,
            Context, subject, _issuer.Seed,
            _clock.GetUtcNow().AddSeconds(-5), _clock.GetUtcNow().AddMinutes(5));
    }

    private static Identity NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return new Identity(key.Export(KeyBlobFormat.RawPrivateKey),
            publicKey, "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed record Identity(byte[] Seed, byte[] PublicKey, string Did);

    private sealed class FakeClock(DateTimeOffset time) : TimeProvider
    {
        private DateTimeOffset _time = time;
        public override DateTimeOffset GetUtcNow() => _time;
        public void Advance(TimeSpan interval) => _time = _time.Add(interval);
    }
}
