using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>Real-key, independently pinned did:web issuer status and one-use holder disclosure gate.</summary>
public sealed class JwtVcJsonPinnedDidWebIssuerStatusTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string Method = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");

    [Fact]
    public void GenuineFreshIssuerNotRevokedAndHolderProofReleaseClaimsOnlyOnce()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            Check(f, status, f.IssuerPublicKey, out JsonElement subject));
        Assert.Equal("member", subject.GetProperty("role").GetString());
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, status, f.IssuerPublicKey, out JsonElement replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void GenuineIssuerRevokedStatusSpendsProofAndNeverReleasesClaims()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: true);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            Check(f, status, f.IssuerPublicKey, out JsonElement subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, CreateStatus(f, revoked: false), f.IssuerPublicKey, out _));
    }

    [Fact]
    public void ForgedIssuerStatusCannotReleaseClaimsOrImpersonateEnrolledKey()
    {
        Fixture f = CreateFixture();
        var foreign = Identity();
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonPinnedDidWebIssuerStatus.Create(
                f.CredentialJwt, IssuerDid, Method, f.IssuerPublicKey,
                foreign.Seed, revoked: false, f.Clock.GetUtcNow(), f.Clock));

        string authentic = CreateStatus(f, revoked: false);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, authentic, foreign.PublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            Check(f, authentic, f.IssuerPublicKey, out _));
    }

    [Fact]
    public void AbsentIssuerStatusFailsWithoutSpendingValidHolderChallenge()
    {
        Fixture f = CreateFixture();
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, string.Empty, f.IssuerPublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            Check(f, CreateStatus(f, revoked: false), f.IssuerPublicKey, out _));
    }


    [Fact]
    public void FreshGenuineStatusForDifferentIssuerJwtCannotClearPresentedCredential()
    {
        Fixture f = CreateFixture();
        string changedPayload = Ed25519JwtSigner.ExtractPayload(f.CredentialJwt)
            .Replace("\"role\":\"member\"", "\"role\":\"visitor\"", StringComparison.Ordinal);
        Assert.NotEqual(Ed25519JwtSigner.ExtractPayload(f.CredentialJwt), changedPayload);
        string secondOriginal = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(f.CredentialJwt),
            changedPayload, f.IssuerSeed);
        string status = JwtVcJsonPinnedDidWebIssuerStatus.Create(
            secondOriginal, IssuerDid, Method, f.IssuerPublicKey,
            f.IssuerSeed, revoked: false, f.Clock.GetUtcNow(), f.Clock);

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, status, f.IssuerPublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, CreateStatus(f, revoked: false), f.IssuerPublicKey, out _));
    }

    [Fact]
    public void AuthenticallySignedButExpiredStatusCannotReleaseClaims()
    {
        var clock = new AdjustableClock(new DateTimeOffset(2026, 11, 6, 23, 0, 0, TimeSpan.Zero));
        Fixture f = CreateFixture(clock);
        string status = CreateStatus(f, revoked: false);
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, status, f.IssuerPublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
    }

    [Fact]
    public void ReSignedStatusWithAnotherAssertionMethodIsNotTrusted()
    {
        Fixture f = CreateFixture();
        string authentic = CreateStatus(f, revoked: false);
        string changedHeader = Ed25519JwtSigner.ExtractHeader(authentic)
            .Replace("#key-2", "#key-1", StringComparison.Ordinal);
        string foreignMethod = Ed25519JwtSigner.CreateSignedJwt(
            changedHeader, Ed25519JwtSigner.ExtractPayload(authentic),
            f.IssuerSeed);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            Check(f, foreignMethod, f.IssuerPublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
    }

    [Fact]
    public void CombinedAdmissionReleasesOnlyWhenBothIndependentPoliciesPassOnce()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            CheckAdmission(f, status, [], f.IssuerPublicKey, out JsonElement subject));
        Assert.Equal("member", subject.GetProperty("role").GetString());
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, status, [], f.IssuerPublicKey, out JsonElement replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void CombinedAdmissionLocalDenialOverridesFreshIssuerNotRevokedAndSpendsChallenge()
    {
        Fixture f = CreateFixture();
        string originalDigest = Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(f.CredentialJwt)));
        string status = CreateStatus(f, revoked: false);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.DeniedByVerifier,
            CheckAdmission(f, status, [originalDigest], f.IssuerPublicKey,
                out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, status, [], f.IssuerPublicKey, out _));
    }

    [Fact]
    public void CombinedAdmissionIssuerRevocationSpendsChallengeWithoutDisclosingClaims()
    {
        Fixture f = CreateFixture();
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.RevokedByIssuer,
            CheckAdmission(f, CreateStatus(f, revoked: true), [],
                f.IssuerPublicKey, out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, CreateStatus(f, revoked: false), [],
                f.IssuerPublicKey, out _));
    }

    [Fact]
    public void CombinedAdmissionMissingStatusOrInvalidDenylistDoNotSpendChallenge()
    {
        Fixture f = CreateFixture();
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(f.CredentialJwt)));
        string fresh = CreateStatus(f, revoked: false);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, fresh, ["not-a-digest"], f.IssuerPublicKey, out _));
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, fresh, [digest, digest], f.IssuerPublicKey, out _));
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, string.Empty, [], f.IssuerPublicKey, out _));
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            CheckAdmission(f, fresh, [], f.IssuerPublicKey, out JsonElement subject));
        Assert.Equal("member", subject.GetProperty("role").GetString());
    }

    [Fact]
    public void CombinedAdmissionRejectsForeignIssuerKeyAndWrongOriginalStatus()
    {
        Fixture f = CreateFixture();
        var foreign = Identity();
        string good = CreateStatus(f, revoked: false);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, good, [], foreign.PublicKey, out JsonElement wrongKey));
        Assert.Equal(JsonValueKind.Undefined, wrongKey.ValueKind);

        string changed = Ed25519JwtSigner.ExtractPayload(f.CredentialJwt)
            .Replace("\"role\":\"member\"", "\"role\":\"visitor\"",
                StringComparison.Ordinal);
        string anotherCredential = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(f.CredentialJwt), changed, f.IssuerSeed);
        string foreignStatus = JwtVcJsonPinnedDidWebIssuerStatus.Create(
            anotherCredential, IssuerDid, Method, f.IssuerPublicKey,
            f.IssuerSeed, revoked: false, f.Clock.GetUtcNow(), f.Clock);

        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, foreignStatus, [], f.IssuerPublicKey,
                out JsonElement wrongOriginal));
        Assert.Equal(JsonValueKind.Undefined, wrongOriginal.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, good, [], f.IssuerPublicKey, out _));
    }

    private static JwtVcJsonPinnedDidWebIssuerAdmissionResult CheckAdmission(
        Fixture f, string status, IReadOnlyCollection<string> denied,
        byte[] issuerPublicKey, out JsonElement subject) =>
        JwtVcJsonPinnedDidWebIssuerAdmission.Check(
            f.PresentationJwt, status, f.Tenant, f.Audience, f.Nonce,
            IssuerDid, Method, issuerPublicKey, IssuerName, CredentialId,
            CredentialType, Context, denied, f.Store, f.Clock, out subject);

    private static string CreateStatus(Fixture f, bool revoked) =>
        JwtVcJsonPinnedDidWebIssuerStatus.Create(
            f.CredentialJwt, IssuerDid, Method, f.IssuerPublicKey,
            f.IssuerSeed, revoked, f.Clock.GetUtcNow(), f.Clock);

    private static RevocationSnapshotCheckResult Check(
        Fixture f, string status, byte[] issuerPublicKey, out JsonElement subject) =>
        JwtVcJsonPinnedDidWebIssuerStatus.CheckPresentation(
            f.PresentationJwt, status, f.Tenant, f.Audience, f.Nonce,
            IssuerDid, Method, issuerPublicKey, IssuerName, CredentialId,
            CredentialType, Context, f.Store, f.Clock, out subject);

    private static Fixture CreateFixture(TimeProvider? suppliedClock = null)
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        TimeProvider clock = suppliedClock ?? TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + verifier.Did;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(tenant, audience, IssuerDid);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, role = "member" }));
        DateTimeOffset now = clock.GetUtcNow();
        string credential = JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, Method, issuer.PublicKey, holder.Did, CredentialType, Context,
            document.RootElement, issuer.Seed, now.AddMinutes(-1), now.AddMinutes(4),
            IssuerName, CredentialId);
        string vp = JwtVcJsonPinnedDidWebIssuerPresentation.Create(
            challenge, credential, IssuerDid, Method, issuer.PublicKey,
            IssuerName, CredentialId, CredentialType, Context,
            holder.Did, holder.Seed, clock);
        return new Fixture(credential, vp, tenant, audience, challenge.Nonce,
            issuer.Seed, issuer.PublicKey, store, clock);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }

    private sealed class AdjustableClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan elapsed) => _now = _now.Add(elapsed);
    }

    private sealed record Fixture(
        string CredentialJwt, string PresentationJwt, Guid Tenant, string Audience,
        string Nonce, byte[] IssuerSeed, byte[] IssuerPublicKey,
        IPresentationChallengeStore Store, TimeProvider Clock);
}
