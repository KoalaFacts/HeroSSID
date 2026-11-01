using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Real guardian and successor keys, two HTTP hosts and one shared PostgreSQL
/// challenge store. Verification does not promote an issuer or grant authority.
/// </summary>
public sealed class IssuerGuardianRecoveryHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string ChallengeRoute = "/api/v1/credentials/issuer-guardian-recovery/challenge";
    private const string EnrolledChallengeRoute = "/api/v1/credentials/issuer-guardian-recovery/enrolled-challenge";
    private const string EnrolledVerifyRoute = "/api/v1/credentials/issuer-guardian-recovery/enrolled-verify";
    private const string HostPinnedChallengeRoute = "/api/v1/credentials/issuer-guardian-recovery/host-pinned-challenge";
    private const string HostPinnedVerifyRoute = "/api/v1/credentials/issuer-guardian-recovery/host-pinned-verify";
    private const string VerifyRoute = "/api/v1/credentials/issuer-guardian-recovery/verify";
    private const string CancelRoute = "/api/v1/credentials/issuer-guardian-recovery/cancel";
    private const string Audience = "https://verifier.example/issuer-guardian-recovery";
    private readonly DatabaseFixture _fixture = fixture;
    private static readonly SemaphoreSlim MigrationGate = new(1, 1);

    [Fact]
    public async Task GenuineGuardianQuorumSucceedsAcrossHostsOnlyOnceAndFailedPolicyDoesNotBurnNonce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string token = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string secondToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardian1 = NewKey();
        using var guardian2 = NewKey();
        using var foreignGuardian = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string guardian1Did = DidFromKey(guardian1);
        string guardian2Did = DidFromKey(guardian2);

        using var issued = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        JsonElement challenge = await ReadJsonAsync(issued).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        Assert.Equal(Audience, challenge.GetProperty("audience").GetString());
        Assert.Equal(oldDid, challenge.GetProperty("trustedPreviousIssuerDid").GetString());

        string evidence = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardian1Did] = guardian1.Export(KeyBlobFormat.RawPrivateKey),
                [guardian2Did] = guardian2.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);

        using var untrusted = await PostAsync(second, VerifyRoute,
            new
            {
                evidenceJson = evidence, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { guardian1Did, DidFromKey(foreignGuardian) },
                requiredGuardianSignatures = 2
            }, secondToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, untrusted.StatusCode);
        JsonElement rejected = await ReadJsonAsync(untrusted).ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("successorIssuerDid").ValueKind);

        var validRequest = new
        {
            evidenceJson = evidence, audience = Audience, nonce,
            trustedPreviousIssuerDid = oldDid,
            trustedGuardianDids = new[] { guardian1Did, guardian2Did },
            requiredGuardianSignatures = 2
        };
        using var accepted = await PostAsync(second, VerifyRoute, validRequest, secondToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement valid = await ReadJsonAsync(accepted).ConfigureAwait(true);
        Assert.Equal("ValidRecoveryEvidence", valid.GetProperty("status").GetString());
        Assert.Equal(newDid, valid.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(first, VerifyRoute, validRequest, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        JsonElement replayBody = await ReadJsonAsync(replay).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayBody.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryCannotConsumeAnOrdinaryIssuerSuccessorChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardian1 = NewKey();
        using var guardian2 = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string guardian1Did = DidFromKey(guardian1);
        string guardian2Did = DidFromKey(guardian2);

        using var ordinary = await PostAsync(client, "/api/v1/credentials/issuer-successor/challenge",
            new { audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, ordinary.StatusCode);
        string nonce = (await ReadJsonAsync(ordinary).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string evidence = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardian1Did] = guardian1.Export(KeyBlobFormat.RawPrivateKey),
                [guardian2Did] = guardian2.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        using var denied = await PostAsync(client, VerifyRoute,
            new
            {
                evidenceJson = evidence, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { guardian1Did, guardian2Did },
                requiredGuardianSignatures = 2
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        JsonElement result = await ReadJsonAsync(denied).ConfigureAwait(true);
        Assert.Equal("Invalid", result.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryRoutesRequireScopesAndRejectInsecureOrAmbiguousPolicy()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var previous = NewKey();
        string oldDid = DidFromKey(previous);
        var issueRequest = new
        {
            audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120
        };
        using var anonymous = await client.PostAsJsonAsync(ChallengeRoute, issueRequest,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var missingManagement = await PostAsync(client, ChallengeRoute,
            issueRequest, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingManagement.StatusCode);

        string manageOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var missingVerify = await PostAsync(client, ChallengeRoute,
            issueRequest, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingVerify.StatusCode);
        using var invalidVerifyScope = await PostAsync(client, VerifyRoute,
            new { evidenceJson = "invalid" }, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, invalidVerifyScope.StatusCode);

        string both = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var insecure = await PostAsync(client, ChallengeRoute,
            new { audience = "http://verifier.example/recovery", previousIssuerDid = oldDid, lifetimeSeconds = 120 },
            both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, insecure.StatusCode);
        using var malformed = await PostAsync(client, VerifyRoute,
            new
            {
                evidenceJson = "invalid", audience = Audience,
                nonce = "short", trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = Array.Empty<string>(), requiredGuardianSignatures = 2
            }, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
    }

    [Fact]
    public async Task IncidentCancellationAcrossIndependentHostsBlocksGenuineRecovery()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string issuerToken = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string cancelToken = await GetTokenAsync(second, "credential:verify did:manage").ConfigureAwait(true);
        string verifyToken = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);

        using var previous = NewKey();
        using var successor = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string previousDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);
        string firstGuardianDid = DidFromKey(guardianOne);
        string secondGuardianDid = DidFromKey(guardianTwo);

        using var issued = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = previousDid, lifetimeSeconds = 120 },
            issuerToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        string nonce = (await ReadJsonAsync(issued).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string proof = IssuerGuardianRecovery.Create(previousDid, successorDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstGuardianDid] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [secondGuardianDid] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);

        using var cancelled = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce, trustedPreviousIssuerDid = previousDid },
            cancelToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var repeated = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce, trustedPreviousIssuerDid = previousDid },
            cancelToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeated.StatusCode);

        using var rejected = await PostAsync(first, VerifyRoute,
            new
            {
                evidenceJson = proof, audience = Audience, nonce,
                trustedPreviousIssuerDid = previousDid,
                trustedGuardianDids = new[] { firstGuardianDid, secondGuardianDid },
                requiredGuardianSignatures = 2
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        JsonElement denied = await ReadJsonAsync(rejected).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task RecoveryCancellationRequiresBothScopesAndDoesNotExposeUnknownChallenges()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var previous = NewKey();
        string previousDid = DidFromKey(previous);
        var cancellation = new
        {
            audience = Audience,
            nonce = new string('A', 43),
            trustedPreviousIssuerDid = previousDid
        };

        using var anonymous = await client.PostAsJsonAsync(CancelRoute, cancellation,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync(client, "credential:verify").ConfigureAwait(true);
        using var cannotCancel = await PostAsync(client, CancelRoute,
            cancellation, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, cannotCancel.StatusCode);

        string manageOnly = await GetTokenAsync(client, "did:manage").ConfigureAwait(true);
        using var cannotCancelWithoutVerify = await PostAsync(client, CancelRoute,
            cancellation, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, cannotCancelWithoutVerify.StatusCode);

        string authorized = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var invalidNonce = await PostAsync(client, CancelRoute,
            new { audience = Audience, nonce = "short", trustedPreviousIssuerDid = previousDid },
            authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, invalidNonce.StatusCode);

        using var unknown = await PostAsync(client, CancelRoute,
            cancellation, authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unknown.StatusCode);
    }

    [Fact]
    public async Task PolicyBoundChallengeEnforcesIssuancePinsAcrossIndependentHttpHosts()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string issueToken = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string verifyToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        using var rogue = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string firstPin = DidFromKey(guardianOne);
        string secondPin = DidFromKey(guardianTwo);
        string roguePin = DidFromKey(rogue);
        var boundIssue = new
        {
            audience = Audience, previousIssuerDid = oldDid, lifetimeSeconds = 120,
            trustedGuardianDids = new[] { firstPin, secondPin },
            requiredGuardianSignatures = 2
        };
        using var issued = await PostAsync(first, ChallengeRoute, boundIssue,
            issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        JsonElement response = await ReadJsonAsync(issued).ConfigureAwait(true);
        Assert.True(response.GetProperty("guardianPolicyBound").GetBoolean());
        string nonce = response.GetProperty("nonce").GetString()!;

        string rogueProof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstPin] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [roguePin] = rogue.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        using var bad = await PostAsync(second, VerifyRoute,
            new
            {
                evidenceJson = rogueProof, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { firstPin, roguePin },
                requiredGuardianSignatures = 2
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, bad.StatusCode);
        JsonElement denied = await ReadJsonAsync(bad).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);

        string genuineProof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstPin] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [secondPin] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        using var good = await PostAsync(second, VerifyRoute,
            new
            {
                evidenceJson = genuineProof, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { secondPin, firstPin },
                requiredGuardianSignatures = 2
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        JsonElement accepted = await ReadJsonAsync(good).ConfigureAwait(true);
        Assert.Equal("ValidRecoveryEvidence", accepted.GetProperty("status").GetString());
        Assert.Equal(newDid, accepted.GetProperty("successorIssuerDid").GetString());

        using var partial = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = oldDid, trustedGuardianDids = new[] { firstPin, secondPin } },
            issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, partial.StatusCode);
        using var duplicate = await PostAsync(first, ChallengeRoute,
            new { audience = Audience, previousIssuerDid = oldDid, trustedGuardianDids = new[] { firstPin, firstPin }, requiredGuardianSignatures = 2 },
            issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);

        using var secondIssue = await PostAsync(first, ChallengeRoute, boundIssue,
            issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, secondIssue.StatusCode);
        string cancelledNonce = (await ReadJsonAsync(secondIssue).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string cancelledProof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstPin] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [secondPin] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), cancelledNonce, TimeProvider.System);
        string cancelToken = await GetTokenAsync(second, "credential:verify did:manage").ConfigureAwait(true);
        using var cancelled = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce = cancelledNonce, trustedPreviousIssuerDid = oldDid },
            cancelToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var afterCancel = await PostAsync(first, VerifyRoute,
            new
            {
                evidenceJson = cancelledProof, audience = Audience, nonce = cancelledNonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { firstPin, secondPin },
                requiredGuardianSignatures = 2
            }, issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, afterCancel.StatusCode);
        JsonElement invalid = await ReadJsonAsync(afterCancel).ConfigureAwait(true);
        Assert.Equal("Invalid", invalid.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, invalid.GetProperty("successorIssuerDid").ValueKind);
    }


    [Fact]
    public async Task HostPinnedEnrollmentUsesTrustedServerConfigAcrossHostsAndRejectsReplay()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var issuer = NewKey();
        using var successor = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string oldDid = DidFromKey(issuer);
        string newDid = DidFromKey(successor);
        string firstGuardian = DidFromKey(guardianOne);
        string secondGuardian = DidFromKey(guardianTwo);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string policy = IssuerGuardianRecoveryEnrollment.Create(oldDid,
            issuer.Export(KeyBlobFormat.RawPrivateKey),
            [firstGuardian, secondGuardian], 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(3));
        string pin = IssuerGuardianRecoveryEnrollment.Fingerprint(policy);
        var trustedConfig = new Dictionary<string, string?>
        {
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] = HeroDbContext.DefaultTenantId.ToString(),
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = oldDid,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = policy,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] = pin
        };

        await using var firstHost = NewHost(trustedConfig);
        await using var secondHost = NewHost(trustedConfig);
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string issueToken = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string verifyToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);

        using var issued = await PostAsync(first, HostPinnedChallengeRoute,
            new { audience = Audience, trustedPreviousIssuerDid = oldDid, lifetimeSeconds = 120 },
            issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        JsonElement challenge = await ReadJsonAsync(issued).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        Assert.True(challenge.GetProperty("exactEnrollmentBound").GetBoolean());

        string proof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstGuardian] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [secondGuardian] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        var verify = new
        {
            audience = Audience, trustedPreviousIssuerDid = oldDid,
            nonce, evidenceJson = proof
        };
        using var accepted = await PostAsync(second, HostPinnedVerifyRoute,
            verify, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement acceptedBody = await ReadJsonAsync(accepted).ConfigureAwait(true);
        Assert.Equal("ValidRecoveryEvidence", acceptedBody.GetProperty("status").GetString());
        Assert.Equal(newDid, acceptedBody.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(first, HostPinnedVerifyRoute,
            verify, issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        JsonElement denied = await ReadJsonAsync(replay).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);
    }

    [Fact]
    public async Task HostPinnedEnrollmentRejectsAbsentMismatchedAndCrossTenantOperatorPins()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var issuer = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string oldDid = DidFromKey(issuer);
        string guardianOneDid = DidFromKey(guardianOne);
        string guardianTwoDid = DidFromKey(guardianTwo);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string original = IssuerGuardianRecoveryEnrollment.Create(oldDid,
            issuer.Export(KeyBlobFormat.RawPrivateKey),
            [guardianOneDid, guardianTwoDid], 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(3));

        var badPinConfig = new Dictionary<string, string?>
        {
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] = HeroDbContext.DefaultTenantId.ToString(),
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = oldDid,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = original,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] = new string('0', 64)
        };
        // A malformed but syntactically valid operator pin must prevent
        // startup, not leave a running verifier that silently cannot recover.
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var wrongHost = NewHost(badPinConfig);
            using var wrong = wrongHost.CreateClient();
        });

        await using var missingHost = NewHost();
        using var missing = missingHost.CreateClient();
        string missingToken = await GetTokenAsync(missing, "credential:verify did:manage").ConfigureAwait(true);
        var request = new { audience = Audience, trustedPreviousIssuerDid = oldDid, lifetimeSeconds = 120 };

        using var noRegistry = await PostAsync(missing, HostPinnedChallengeRoute,
            request, missingToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, noRegistry.StatusCode);

        badPinConfig["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] =
            IssuerGuardianRecoveryEnrollment.Fingerprint(original);
        badPinConfig["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] =
            Guid.NewGuid().ToString();
        await using var foreignHost = NewHost(badPinConfig);
        using var foreign = foreignHost.CreateClient();
        string foreignToken = await GetTokenAsync(foreign, "credential:verify did:manage").ConfigureAwait(true);
        using var wrongTenant = await PostAsync(foreign, HostPinnedChallengeRoute,
            request, foreignToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, wrongTenant.StatusCode);
    }

    [Fact]
    public void HostPinnedStartupRejectsForgedSignatureDespiteMatchingConfiguredDigest()
    {
        using var originalIssuer = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string issuerDid = DidFromKey(originalIssuer);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string genuineJwt = IssuerGuardianRecoveryEnrollment.Create(
            issuerDid, originalIssuer.Export(KeyBlobFormat.RawPrivateKey),
            [DidFromKey(guardianOne), DidFromKey(guardianTwo)],
            2, new Uri(Audience), now.AddMinutes(-1), now.AddHours(2));
        string[] jwtParts = genuineJwt.Split('.');
        char[] forgedSignature = jwtParts[2].ToCharArray();
        forgedSignature[0] = forgedSignature[0] == 'A' ? 'B' : 'A';
        jwtParts[2] = new string(forgedSignature);
        string forgedJwt = string.Join(".", jwtParts);
        string matchingButUnapprovedDigest = IssuerGuardianRecoveryEnrollment.Fingerprint(forgedJwt);
        var config = new Dictionary<string, string?>
        {
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] = HeroDbContext.DefaultTenantId.ToString(),
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = issuerDid,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = forgedJwt,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] = matchingButUnapprovedDigest
        };

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var host = NewHost(config);
            using var client = host.CreateClient();
        });
    }

    [Fact]
    public void HostPinnedStartupRejectsNotYetEffectiveSignedPolicy()
    {
        using var originalIssuer = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string issuerDid = DidFromKey(originalIssuer);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string futureJwt = IssuerGuardianRecoveryEnrollment.Create(
            issuerDid, originalIssuer.Export(KeyBlobFormat.RawPrivateKey),
            [DidFromKey(guardianOne), DidFromKey(guardianTwo)],
            2, new Uri(Audience), now.AddMinutes(15), now.AddHours(2));
        var config = new Dictionary<string, string?>
        {
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] = HeroDbContext.DefaultTenantId.ToString(),
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = issuerDid,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = futureJwt,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] =
                IssuerGuardianRecoveryEnrollment.Fingerprint(futureJwt)
        };

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var host = NewHost(config);
            using var client = host.CreateClient();
        });
    }

    [Fact]
    public async Task ExactPreEnrollmentHttpRecoveryRejectsSubstitutionLegacyAndReplayAcrossHosts()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        string issueToken = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        string verifyToken = await GetTokenAsync(second, "credential:verify").ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var firstGuardian = NewKey();
        using var secondGuardian = NewKey();
        string oldDid = DidFromKey(previous);
        string newDid = DidFromKey(successor);
        string firstPin = DidFromKey(firstGuardian);
        string secondPin = DidFromKey(secondGuardian);
        byte[] previousSeed = previous.Export(KeyBlobFormat.RawPrivateKey);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string original = IssuerGuardianRecoveryEnrollment.Create(
            oldDid, previousSeed, new[] { firstPin, secondPin }, 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(3));
        string originalDigest = IssuerGuardianRecoveryEnrollment.Fingerprint(original);

        using var unpinned = await PostAsync(first, EnrolledChallengeRoute,
            new
            {
                audience = Audience, trustedPreviousIssuerDid = oldDid,
                signedEnrollmentJwt = original, independentlyPinnedSha256 = new string('0', 64),
                lifetimeSeconds = 120
            }, issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, unpinned.StatusCode);

        using var issued = await PostAsync(first, EnrolledChallengeRoute,
            new
            {
                audience = Audience, trustedPreviousIssuerDid = oldDid,
                signedEnrollmentJwt = original, independentlyPinnedSha256 = originalDigest,
                lifetimeSeconds = 120
            }, issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        JsonElement challenge = await ReadJsonAsync(issued).ConfigureAwait(true);
        string nonce = challenge.GetProperty("nonce").GetString()!;
        Assert.True(challenge.GetProperty("exactEnrollmentBound").GetBoolean());

        string proof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstPin] = firstGuardian.Export(KeyBlobFormat.RawPrivateKey),
                [secondPin] = secondGuardian.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);

        // The legacy verification API cannot bypass the exact-enrollment marker.
        using var legacy = await PostAsync(second, VerifyRoute,
            new
            {
                evidenceJson = proof, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                trustedGuardianDids = new[] { firstPin, secondPin },
                requiredGuardianSignatures = 2
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, legacy.StatusCode);
        Assert.Equal("Invalid", (await ReadJsonAsync(legacy).ConfigureAwait(true))
            .GetProperty("status").GetString());

        // Another genuinely old-key-signed enrollment with the same guardian
        // roster is not interchangeable, even when its SHA-256 is also pinned.
        string replacement = IssuerGuardianRecoveryEnrollment.Create(
            oldDid, previousSeed, new[] { firstPin, secondPin }, 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(4));
        using var substituted = await PostAsync(second, EnrolledVerifyRoute,
            new
            {
                evidenceJson = proof, audience = Audience, nonce,
                trustedPreviousIssuerDid = oldDid,
                signedEnrollmentJwt = replacement,
                independentlyPinnedSha256 = IssuerGuardianRecoveryEnrollment.Fingerprint(replacement)
            }, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, substituted.StatusCode);
        JsonElement denied = await ReadJsonAsync(substituted).ConfigureAwait(true);
        Assert.Equal("Invalid", denied.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("successorIssuerDid").ValueKind);

        var valid = new
        {
            evidenceJson = proof, audience = Audience, nonce,
            trustedPreviousIssuerDid = oldDid, signedEnrollmentJwt = original,
            independentlyPinnedSha256 = originalDigest
        };
        using var accepted = await PostAsync(second, EnrolledVerifyRoute,
            valid, verifyToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement acceptedBody = await ReadJsonAsync(accepted).ConfigureAwait(true);
        Assert.Equal("ValidRecoveryEvidence", acceptedBody.GetProperty("status").GetString());
        Assert.Equal(newDid, acceptedBody.GetProperty("successorIssuerDid").GetString());

        using var replay = await PostAsync(first, EnrolledVerifyRoute,
            valid, issueToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal("Invalid", (await ReadJsonAsync(replay).ConfigureAwait(true))
            .GetProperty("status").GetString());
    }

    [Fact]
    public async Task ExactPreEnrollmentHttpRequiresScopesAndSupportsIncidentCancellation()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var firstHost = NewHost();
        await using var secondHost = NewHost();
        using var first = firstHost.CreateClient();
        using var second = secondHost.CreateClient();
        using var old = NewKey();
        using var successor = NewKey();
        using var guardian1 = NewKey();
        using var guardian2 = NewKey();
        string oldDid = DidFromKey(old);
        string newDid = DidFromKey(successor);
        string guardian1Did = DidFromKey(guardian1);
        string guardian2Did = DidFromKey(guardian2);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string policy = IssuerGuardianRecoveryEnrollment.Create(oldDid,
            old.Export(KeyBlobFormat.RawPrivateKey), new[] { guardian1Did, guardian2Did },
            2, new Uri(Audience), now.AddMinutes(-1), now.AddHours(3));
        string digest = IssuerGuardianRecoveryEnrollment.Fingerprint(policy);
        var issue = new
        {
            audience = Audience, trustedPreviousIssuerDid = oldDid,
            signedEnrollmentJwt = policy, independentlyPinnedSha256 = digest,
            lifetimeSeconds = 120
        };

        using var anonymous = await first.PostAsJsonAsync(EnrolledChallengeRoute,
            issue, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        string verifyOnly = await GetTokenAsync(first, "credential:verify").ConfigureAwait(true);
        string manageOnly = await GetTokenAsync(first, "did:manage").ConfigureAwait(true);
        using var missingManage = await PostAsync(first, EnrolledChallengeRoute,
            issue, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingManage.StatusCode);
        using var missingVerify = await PostAsync(first, EnrolledChallengeRoute,
            issue, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, missingVerify.StatusCode);

        string both = await GetTokenAsync(first, "credential:verify did:manage").ConfigureAwait(true);
        using var issued = await PostAsync(first, EnrolledChallengeRoute, issue,
            both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        string nonce = (await ReadJsonAsync(issued).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string proof = IssuerGuardianRecovery.Create(oldDid, newDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardian1Did] = guardian1.Export(KeyBlobFormat.RawPrivateKey),
                [guardian2Did] = guardian2.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        var check = new
        {
            evidenceJson = proof, audience = Audience, nonce,
            trustedPreviousIssuerDid = oldDid, signedEnrollmentJwt = policy,
            independentlyPinnedSha256 = digest
        };
        using var cannotVerify = await PostAsync(first, EnrolledVerifyRoute,
            check, manageOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, cannotVerify.StatusCode);

        string canceller = await GetTokenAsync(second, "credential:verify did:manage").ConfigureAwait(true);
        using var cancelled = await PostAsync(second, CancelRoute,
            new { audience = Audience, nonce, trustedPreviousIssuerDid = oldDid },
            canceller).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var rejected = await PostAsync(first, EnrolledVerifyRoute,
            check, both).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        Assert.Equal("Invalid", (await ReadJsonAsync(rejected).ConfigureAwait(true))
            .GetProperty("status").GetString());
    }

    [Fact]
    public async Task OperatorRevocationOfExactEnrollmentBlocksHostRecoveryWithoutConsumingNonce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        using var previous = NewKey();
        using var successor = NewKey();
        using var firstGuardian = NewKey();
        using var secondGuardian = NewKey();
        string oldDid = DidFromKey(previous);
        string successorDid = DidFromKey(successor);
        string firstDid = DidFromKey(firstGuardian);
        string secondDid = DidFromKey(secondGuardian);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string signedPolicy = IssuerGuardianRecoveryEnrollment.Create(
            oldDid, previous.Export(KeyBlobFormat.RawPrivateKey),
            [firstDid, secondDid], 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(2));
        string digest = IssuerGuardianRecoveryEnrollment.Fingerprint(signedPolicy);
        var trusted = new Dictionary<string, string?>
        {
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] =
                HeroDbContext.DefaultTenantId.ToString(),
            ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = oldDid,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = signedPolicy,
            ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] = digest
        };
        await using var host = NewHost(trusted);
        using var client = host.CreateClient();
        string authorized = await GetTokenAsync(client, "credential:verify did:manage")
            .ConfigureAwait(true);
        var issue = new
        {
            audience = Audience,
            trustedPreviousIssuerDid = oldDid,
            lifetimeSeconds = 120
        };
        using var initial = await PostAsync(client, HostPinnedChallengeRoute, issue,
            authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, initial.StatusCode);
        string nonce = (await ReadJsonAsync(initial).ConfigureAwait(true))
            .GetProperty("nonce").GetString()!;
        string evidence = IssuerGuardianRecovery.Create(
            oldDid, successorDid, successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [firstDid] = firstGuardian.Export(KeyBlobFormat.RawPrivateKey),
                [secondDid] = secondGuardian.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), nonce, TimeProvider.System);
        var verify = new
        {
            audience = Audience,
            trustedPreviousIssuerDid = oldDid,
            nonce,
            evidenceJson = evidence
        };

        // The operator revokes the exact pre-incident approved fingerprint via a
        // reloadable configuration provider while the process remains alive.
        host.Services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>()[
            "IssuerGuardianEnrollmentTrust:RevokedSha256:0"] = digest;

        using var blockedVerify = await PostAsync(client, HostPinnedVerifyRoute,
            verify, authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, blockedVerify.StatusCode);
        JsonElement body = await ReadJsonAsync(blockedVerify).ConfigureAwait(true);
        Assert.Equal("Invalid", body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("successorIssuerDid").ValueKind);

        using var blockedIssue = await PostAsync(client, HostPinnedChallengeRoute,
            issue, authorized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, blockedIssue.StatusCode);

        // A separate verifier replica configured with the same denied digest
        // must also reject the genuine signed proof, even without a restart race.
        var deniedConfig = new Dictionary<string, string?>(trusted)
        {
            ["IssuerGuardianEnrollmentTrust:RevokedSha256:0"] = digest
        };
        await using var deniedHost = NewHost(deniedConfig);
        using var deniedClient = deniedHost.CreateClient();
        string deniedToken = await GetTokenAsync(deniedClient, "credential:verify")
            .ConfigureAwait(true);
        using var denied = await PostAsync(deniedClient, HostPinnedVerifyRoute,
            verify, deniedToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        Assert.Equal("Invalid", (await ReadJsonAsync(denied).ConfigureAwait(true))
            .GetProperty("status").GetString());

        // Malformed operator revocations must fail closed before the host serves.
        var invalid = new Dictionary<string, string?>(trusted)
        {
            ["IssuerGuardianEnrollmentTrust:RevokedSha256:0"] = "not-a-sha256"
        };
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var invalidHost = NewHost(invalid);
            using var invalidClient = invalidHost.CreateClient();
        });
    }

    private async Task EnsureMigratedAsync()
    {
        // xUnit v3 may run facts in this class concurrently. These facts share
        // one Testcontainers database: two simultaneous EF migrations can both
        // try to create credential_offers. Serialize only that schema setup;
        // do not skip tests, change migrations or hide any failures.
        await MigrationGate.WaitAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        try
        {
            await using var db = _fixture.CreateDbContext<HeroDbContext>();
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        }
        finally
        {
            MigrationGate.Release();
        }
    }

    private WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest> NewHost(
        Dictionary<string, string?>? trustedConfig = null) =>
        new ConfiguredHost(_fixture.ConnectionString, trustedConfig);

    private sealed class ConfiguredHost(
        string connectionString, Dictionary<string, string?>? trustedConfig)
        : WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-guardian-recovery-http-test-secret-more-than-32-bytes"
                };
                if (trustedConfig is not null)
                {
                    foreach (var entry in trustedConfig)
                    {
                        values.Add(entry.Key, entry.Value);
                    }
                }
                configuration.AddInMemoryCollection(values);
            });
        }
    }

    private static async Task<string> GetTokenAsync(HttpClient client, string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await client.PostAsync("/oauth2/token", form,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement body = await ReadJsonAsync(response).ConfigureAwait(true);
        return body.GetProperty("access_token").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
