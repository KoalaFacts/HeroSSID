using System.Security.Cryptography;
using System.Text;
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
            JwtVcJsonRevocationSnapshot.Check(snapshot, anotherCredential,
                _issuer.Did, _clock.GetUtcNow()));
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
        string foreignStatus = JwtVcJsonRevocationSnapshot.Create(
            _foreign.Did, [], _foreign.Seed, _clock.GetUtcNow(), _clock);

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


    [Fact]
    public void BoundHolderWithFreshSignedIssuerStatusReleasesClaimsOnce()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string credential = Issue("active");
        string form = BoundForm(original, credential);
        string pin = Pin(original);
        string snapshot = Snapshot([]);

        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            CheckBound(form, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var claims));
        Assert.Equal(_holder.Did, claims.GetProperty("id").GetString());
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void BoundStatusRejectsLegacyAndSignedSameNonceReplacementWithoutSpending()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string pin = Pin(original);
        string credential = Issue("active");
        string snapshot = Snapshot([]);
        string legacy = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            original, _verifier.Did, Callback, CredentialType, Context,
            credential, _holder.Did, _holder.Seed, _clock);
        string bound = BoundForm(original, credential);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(legacy, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var legacyClaims));
        Assert.Equal(JsonValueKind.Undefined, legacyClaims.ValueKind);

        _clock.Advance(TimeSpan.FromSeconds(1));
        string replacement = Request(challenge);
        Assert.NotEqual(original, replacement);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(bound, snapshot, replacement, pin, tenant, challenge.Nonce, store,
                out var replacedClaims));
        Assert.Equal(JsonValueKind.Undefined, replacedClaims.ValueKind);

        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            CheckBound(bound, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    [Fact]
    public void BoundRevokedCredentialSpendsNonceButNeverDisclosesClaims()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string credential = Issue("revoked");
        string form = BoundForm(original, credential);
        string pin = Pin(original);
        string snapshot = Snapshot([credential]);

        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            CheckBound(form, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void MissingStatusOrForeignTenantCannotConsumeBoundChallenge()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string form = BoundForm(original, Issue("active"));
        string pin = Pin(original);
        string snapshot = Snapshot([]);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, "", original, pin, tenant, challenge.Nonce, store,
                out var missing));
        Assert.Equal(JsonValueKind.Undefined, missing.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, snapshot, original, pin, Guid.NewGuid(), challenge.Nonce,
                store, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            CheckBound(form, snapshot, original, pin, tenant, challenge.Nonce, store,
                out var accepted));
        Assert.Equal(_holder.Did, accepted.GetProperty("id").GetString());
    }

    [Fact]
    public void AuthenticBoundPresentationWithWrongIssuerStatusNeverReleasesClaims()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string form = BoundForm(original, Issue("active"));
        string foreignSnapshot = JwtVcJsonRevocationSnapshot.Create(
            _foreign.Did, [], _foreign.Seed, _clock.GetUtcNow(), _clock);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, foreignSnapshot, original, Pin(original), tenant,
                challenge.Nonce, store, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBound(form, Snapshot([]), original, Pin(original), tenant,
                challenge.Nonce, store, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void IncidentCutoffAcceptsAuthenticAtBoundaryAndRejectsReplay()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string form = BoundForm(original, Issue("active"));
        DateTimeOffset cutoff = _clock.GetUtcNow();
        string status = Snapshot([]);

        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            CheckBoundWithCutoff(form, status, original, Pin(original),
                tenant, challenge.Nonce, store, cutoff, out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBoundWithCutoff(form, status, original, Pin(original),
                tenant, challenge.Nonce, store, cutoff, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void AuthenticPreIncidentStatusIsDeniedAndSpendsBoundChallenge()
    {
        string beforeIncident = Snapshot([]);
        _clock.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset cutoff = _clock.GetUtcNow();
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string form = BoundForm(original, Issue("active"));

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBoundWithCutoff(form, beforeIncident, original, Pin(original),
                tenant, challenge.Nonce, store, cutoff, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBoundWithCutoff(form, Snapshot([]), original, Pin(original),
                tenant, challenge.Nonce, store, cutoff, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void FutureCutoffIsInvalidWithoutSpendingHolderChallenge()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string form = BoundForm(original, Issue("active"));
        string status = Snapshot([]);
        DateTimeOffset future = _clock.GetUtcNow().AddSeconds(1);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            CheckBoundWithCutoff(form, status, original, Pin(original),
                tenant, challenge.Nonce, store, future, out var invalid));
        Assert.Equal(JsonValueKind.Undefined, invalid.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            CheckBoundWithCutoff(form, status, original, Pin(original),
                tenant, challenge.Nonce, store, _clock.GetUtcNow(), out var accepted));
        Assert.Equal(_holder.Did, accepted.GetProperty("id").GetString());
    }

    [Fact]
    public void IncidentCutoffCannotReleaseAuthenticallyRevokedClaims()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string original = Request(challenge);
        string credential = Issue("revoked");
        string form = BoundForm(original, credential);
        string status = Snapshot([credential]);

        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            CheckBoundWithCutoff(form, status, original, Pin(original),
                tenant, challenge.Nonce, store, _clock.GetUtcNow(), out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    private RevocationSnapshotCheckResult CheckBoundWithCutoff(
        string form, string status, string request, string pin, Guid tenant,
        string nonce, IPresentationChallengeStore store, DateTimeOffset cutoff,
        out JsonElement claims) =>
        JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseFormWithObservationCutoff(
            form, status, request, pin, _verifier.Did, Callback, tenant,
            Audience, nonce, CredentialType, Context, store, _clock, cutoff, out claims);

    private RevocationSnapshotCheckResult CheckBound(
        string form, string snapshot, string original, string pin,
        Guid tenant, string nonce, IPresentationChallengeStore store,
        out JsonElement claims) =>
        JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseForm(
            form, snapshot, original, pin, _verifier.Did, Callback,
            tenant, Audience, nonce, CredentialType, Context, store, _clock, out claims);

    private string Request(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, Callback, CredentialType,
            Context, _clock);

    private string BoundForm(string request, string credential) =>
        OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            request, _verifier.Did, Callback, CredentialType, Context,
            credential, _holder.Did, _holder.Seed, _clock);

    private static string Pin(string request) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request)));

    private RevocationSnapshotCheckResult Check(string form, string snapshot, Guid tenant,
        string nonce, IPresentationChallengeStore store, out JsonElement claims) =>
        JwtVcJsonDirectPostRevocation.CheckResponseForm(form, snapshot, tenant, Audience,
            nonce, CredentialType, Context, store, _clock, out claims);

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(_issuer.Did, revoked, _issuer.Seed,
            _clock.GetUtcNow(), _clock);

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
