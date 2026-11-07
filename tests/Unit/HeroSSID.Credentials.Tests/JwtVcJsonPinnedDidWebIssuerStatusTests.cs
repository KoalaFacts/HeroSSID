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

    [Fact]
    public void CombinedAdmissionForgedIssuerStatusConsumesGenuineProofWithoutClaimDisclosure()
    {
        Fixture f = CreateFixture();
        var attacker = Identity();
        string genuineStatus = CreateStatus(f, revoked: false);
        string forgedStatus = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(genuineStatus),
            Ed25519JwtSigner.ExtractPayload(genuineStatus), attacker.Seed);

        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, forgedStatus, [], f.IssuerPublicKey,
                out JsonElement rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            CheckAdmission(f, genuineStatus, [], f.IssuerPublicKey, out _));
    }

    [Fact]
    public void WalletPreflightShowsAuthenticatedClaimsBeforeKeyUseAndSignsOnlyAfterApproval()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.True(PrepareWallet(f, status, f.CredentialJwt, f.IssuerPublicKey,
            f.Challenge, out var preview));
        Assert.NotNull(preview);
        Assert.Equal("member", preview.VerifiedSubject.GetProperty("role").GetString());

        string holderVp = JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
            preview, f.Challenge, f.CredentialJwt, status,
            f.IssuerPublicKey, f.HolderSeed, f.Clock);
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            JwtVcJsonPinnedDidWebIssuerPresentation.Check(
                holderVp, f.Tenant, f.Audience, f.Nonce,
                IssuerDid, Method, f.IssuerPublicKey, IssuerName,
                CredentialId, CredentialType, Context, f.Store, f.Clock,
                out JsonElement admitted));
        Assert.Equal("member", admitted.GetProperty("role").GetString());
    }

    [Fact]
    public void WalletPreflightRefusesRevokedForgedForeignOrMissingStatusWithoutDisclosure()
    {
        Fixture f = CreateFixture();
        var attacker = Identity();
        string validStatus = CreateStatus(f, revoked: false);
        string forgedStatus = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(validStatus),
            Ed25519JwtSigner.ExtractPayload(validStatus), attacker.Seed);

        Assert.False(PrepareWallet(f, CreateStatus(f, revoked: true),
            f.CredentialJwt, f.IssuerPublicKey, f.Challenge, out var revoked));
        Assert.Null(revoked);
        Assert.False(PrepareWallet(f, forgedStatus,
            f.CredentialJwt, f.IssuerPublicKey, f.Challenge, out var forged));
        Assert.Null(forged);
        Assert.False(PrepareWallet(f, string.Empty,
            f.CredentialJwt, f.IssuerPublicKey, f.Challenge, out var absent));
        Assert.Null(absent);
        Assert.False(PrepareWallet(f, validStatus,
            f.CredentialJwt, attacker.PublicKey, f.Challenge, out var foreign));
        Assert.Null(foreign);
    }

    [Fact]
    public void WalletPostConsentRefusesStatusOrCredentialSwapAndChangedChallenge()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.True(PrepareWallet(f, status, f.CredentialJwt, f.IssuerPublicKey,
            f.Challenge, out var preview));
        Assert.NotNull(preview);

        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
                preview, f.Challenge, f.CredentialJwt, CreateStatus(f, revoked: true),
                f.IssuerPublicKey, f.HolderSeed, f.Clock));

        string differentPayload = Ed25519JwtSigner.ExtractPayload(f.CredentialJwt)
            .Replace("\"role\":\"member\"", "\"role\":\"guest\"",
                StringComparison.Ordinal);
        string anotherCredential = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(f.CredentialJwt),
            differentPayload, f.IssuerSeed);
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
                preview, f.Challenge, anotherCredential, status,
                f.IssuerPublicKey, f.HolderSeed, f.Clock));

        PresentationChallenge changed = f.Challenge with { Audience = "another-verifier" };
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
                preview, changed, f.CredentialJwt, status,
                f.IssuerPublicKey, f.HolderSeed, f.Clock));
    }

    [Fact]
    public void WalletPreflightRejectsStaleStatusAndExpiredVerifierRequest()
    {
        var clock = new AdjustableClock(new DateTimeOffset(2026, 11, 7, 0, 0, 0, TimeSpan.Zero));
        Fixture f = CreateFixture(clock);
        string status = CreateStatus(f, revoked: false);
        Assert.True(PrepareWallet(f, status, f.CredentialJwt, f.IssuerPublicKey,
            f.Challenge, out var preview));
        Assert.NotNull(preview);
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.False(PrepareWallet(f, status, f.CredentialJwt, f.IssuerPublicKey,
            f.Challenge, out var expiredStatus));
        Assert.Null(expiredStatus);
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
                preview, f.Challenge, f.CredentialJwt, status,
                f.IssuerPublicKey, f.HolderSeed, f.Clock));
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.False(PrepareWallet(f, CreateStatus(f, revoked: false),
            f.CredentialJwt, f.IssuerPublicKey, f.Challenge,
            out var expiredChallenge));
        Assert.Null(expiredChallenge);
    }


    [Fact]
    public void WalletEmergencyAllowsRealIssuerStatusAndHolderSignatureOnlyWithClearLocalPolicy()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.True(PrepareEmergency(f, status, [], out var preview));
        Assert.NotNull(preview);
        Assert.Equal("member", preview.Disclosure.VerifiedSubject.GetProperty("role").GetString());

        string vp = JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterEmergencyDenylistPreview(
            preview, f.Challenge, f.CredentialJwt, status, f.IssuerPublicKey,
            [], f.HolderSeed, f.Clock);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked,
            JwtVcJsonPinnedDidWebIssuerAdmission.Check(
                vp, status, f.Tenant, f.Audience, f.Nonce, IssuerDid, Method,
                f.IssuerPublicKey, IssuerName, CredentialId, CredentialType,
                Context, [], f.Store, f.Clock, out JsonElement verified));
        Assert.Equal("member", verified.GetProperty("role").GetString());
    }

    [Fact]
    public void WalletEmergencySuppressesPreviewDespiteAuthenticIssuerSignedNotRevoked()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(f.CredentialJwt)));
        Assert.False(PrepareEmergency(f, status, [digest], out var preview));
        Assert.Null(preview);
    }

    [Fact]
    public void WalletEmergencyRequiresNewConsentIfLocalIncidentPolicyChangesAfterPreview()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        Assert.True(PrepareEmergency(f, status, [], out var preview));
        Assert.NotNull(preview);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(f.CredentialJwt)));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterEmergencyDenylistPreview(
                preview, f.Challenge, f.CredentialJwt, status, f.IssuerPublicKey,
                [digest], f.HolderSeed, f.Clock));

        string unrelatedDigest = new('0', 64);
        Assert.NotEqual(digest, unrelatedDigest);
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterEmergencyDenylistPreview(
                preview, f.Challenge, f.CredentialJwt, status, f.IssuerPublicKey,
                [unrelatedDigest], f.HolderSeed, f.Clock));
    }

    [Fact]
    public void WalletEmergencyRejectsNonCanonicalDuplicateAndOversizedLocalPolicies()
    {
        Fixture f = CreateFixture();
        string status = CreateStatus(f, revoked: false);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(f.CredentialJwt)));
        Assert.False(PrepareEmergency(f, status, ["NOT-A-DIGEST"], out var malformed));
        Assert.Null(malformed);
        Assert.False(PrepareEmergency(f, status, [digest, digest], out var duplicate));
        Assert.Null(duplicate);
        Assert.False(PrepareEmergency(f, status,
            Enumerable.Range(0, 257).Select(static i => i.ToString("x64", System.Globalization.CultureInfo.InvariantCulture)).ToArray(),
            out var oversized));
        Assert.Null(oversized);
        Assert.True(PrepareEmergency(f, status, [new string('0', 64)],
            out var unrelated));
        Assert.NotNull(unrelated);
    }


    private static readonly Uri IssuerStatusUri =
        new("https://issuer.example/status/credential-42.jwt");

    [Fact]
    public async Task PinnedHttpsIssuerStatusGenuinelyUnlocksOnlyNonRevokedWalletPreview()
    {
        Fixture f = CreateFixture();
        string validStatus = CreateStatus(f, revoked: false);
        using var handler = new StatusProbeHandler(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(IssuerStatusUri, request.RequestUri);
            Assert.Null(request.Headers.Authorization);
            return StatusResponse(validStatus);
        });
        using var http = new HttpClient(handler);
        var fetched = await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
            IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
            f.IssuerPublicKey, f.Clock);
        Assert.NotNull(fetched);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed, fetched.Status);
        Assert.Equal(validStatus, fetched.SignedStatusJwt);
        Assert.Equal(1, handler.Calls);
        Assert.True(PrepareWallet(f, fetched.SignedStatusJwt, f.CredentialJwt,
            f.IssuerPublicKey, f.Challenge, out var preview));
        Assert.NotNull(preview);
        Assert.Equal("member", preview.VerifiedSubject.GetProperty("role").GetString());
    }

    [Fact]
    public async Task GenuineIssuerRevocationIsReturnedAsRevokedAndWalletRefusesDisclosure()
    {
        Fixture f = CreateFixture();
        string revokedStatus = CreateStatus(f, revoked: true);
        using var handler = new StatusProbeHandler(_ => StatusResponse(revokedStatus));
        using var http = new HttpClient(handler);
        var fetched = await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
            IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
            f.IssuerPublicKey, f.Clock);
        Assert.NotNull(fetched);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked, fetched.Status);
        Assert.False(PrepareWallet(f, fetched.SignedStatusJwt, f.CredentialJwt,
            f.IssuerPublicKey, f.Challenge, out var preview));
        Assert.Null(preview);
    }

    [Fact]
    public async Task StatusFetchRejectsForgedWrongCredentialAndExpiredObservations()
    {
        var clock = new AdjustableClock(new DateTimeOffset(2026, 11, 7, 0, 0, 0, TimeSpan.Zero));
        Fixture f = CreateFixture(clock);
        string authentic = CreateStatus(f, revoked: false);
        var attacker = Identity();
        string forged = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(authentic),
            Ed25519JwtSigner.ExtractPayload(authentic), attacker.Seed);
        foreach (string result in new[] { forged, authentic })
        {
            using var handler = new StatusProbeHandler(_ => StatusResponse(result));
            using var http = new HttpClient(handler);
            string original = result == forged ? f.CredentialJwt : f.CredentialJwt + "x";
            Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                IssuerStatusUri, http, original, IssuerDid, Method,
                f.IssuerPublicKey, clock));
        }

        clock.Advance(TimeSpan.FromSeconds(61));
        using var expiredHandler = new StatusProbeHandler(_ => StatusResponse(authentic));
        using var expiredHttp = new HttpClient(expiredHandler);
        Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
            IssuerStatusUri, expiredHttp, f.CredentialJwt, IssuerDid, Method,
            f.IssuerPublicKey, clock));
    }

    [Fact]
    public async Task StatusFetchBlocksUnsafeTargetsAndAmbientCredentialDisclosureBeforeNetwork()
    {
        Fixture f = CreateFixture();
        using var handler = new StatusProbeHandler(_ => StatusResponse(CreateStatus(f, false)));
        using var http = new HttpClient(handler);
        foreach (Uri unsafeUri in new[]
        {
            new Uri("http://issuer.example/status/credential-42.jwt"),
            new Uri("https://user:password@issuer.example/status/credential-42.jwt"),
            new Uri("https://issuer.example/status/credential-42.jwt?token=private"),
            new Uri("https://issuer.example:9443/status/credential-42.jwt"),
            new Uri("https://127.0.0.1/status/credential-42.jwt")
        })
        {
            Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                unsafeUri, http, f.CredentialJwt, IssuerDid, Method,
                f.IssuerPublicKey, f.Clock));
        }

        http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "wallet-secret");
        Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
            IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
            f.IssuerPublicKey, f.Clock));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task StatusFetchRejectsRedirectIncorrectMediaTypeAndOversizedBody()
    {
        Fixture f = CreateFixture();
        using (var handler = new StatusProbeHandler(_ =>
            new HttpResponseMessage(System.Net.HttpStatusCode.Redirect)
            { Headers = { Location = new Uri("https://evil.example/collect") } }))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
                f.IssuerPublicKey, f.Clock));
        }

        using (var handler = new StatusProbeHandler(_ =>
            StatusResponse(CreateStatus(f, false), "text/plain")))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
                f.IssuerPublicKey, f.Clock));
        }

        using (var handler = new StatusProbeHandler(_ =>
            StatusResponse(new string('X', 9_000))))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusAsync(
                IssuerStatusUri, http, f.CredentialJwt, IssuerDid, Method,
                f.IssuerPublicKey, f.Clock));
        }
    }


    [Fact]
    public void StatusFetchIsolatedHandlerHasNoAmbientCredentialsOrRedirects()
    {
        using var handler = JwtVcJsonPinnedDidWebIssuerStatusTransport
            .CreateIsolatedStatusTransportHandler();
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.False(handler.UseProxy);
        Assert.False(handler.PreAuthenticate);
        Assert.Null(handler.Credentials);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.Null(handler.ActivityHeadersPropagator);
        Assert.Equal(System.Net.DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(System.Security.Cryptography.X509Certificates.X509RevocationMode.Online,
            handler.SslOptions.CertificateRevocationCheckMode);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.SslOptions.ClientCertificates);
        Assert.Null(handler.SslOptions.LocalCertificateSelectionCallback);
        using var http = new HttpClient(handler);
        Assert.Empty(http.DefaultRequestHeaders);
    }

    private static HttpResponseMessage StatusResponse(string jwt, string mediaType = "application/jwt")
    {
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, System.Text.Encoding.ASCII)
        };
        response.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);
        return response;
    }

    private sealed class StatusProbeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(respond(request));
        }
    }

    private static bool PrepareEmergency(
        Fixture f, string status, IReadOnlyCollection<string> denied,
        out JwtVcJsonPinnedDidWebWalletEmergencyPreview? preview) =>
        JwtVcJsonPinnedDidWebWalletPreflight.TryPrepareWithEmergencyDenylist(
            f.Challenge, f.CredentialJwt, status, IssuerDid, Method, f.IssuerPublicKey,
            IssuerName, CredentialId, CredentialType, Context, f.HolderDid,
            denied, f.Clock, out preview);

    private static bool PrepareWallet(
        Fixture f, string status, string originalJwt, byte[] publicKey,
        PresentationChallenge challenge,
        out JwtVcJsonPinnedDidWebWalletPreview? preview) =>
        JwtVcJsonPinnedDidWebWalletPreflight.TryPrepare(
            challenge, originalJwt, status, IssuerDid, Method, publicKey,
            IssuerName, CredentialId, CredentialType, Context, f.HolderDid,
            f.Clock, out preview);

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
            issuer.Seed, issuer.PublicKey, store, clock,
            challenge, holder.Did, holder.Seed);
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
        IPresentationChallengeStore Store, TimeProvider Clock,
        PresentationChallenge Challenge, string HolderDid, byte[] HolderSeed);
}
