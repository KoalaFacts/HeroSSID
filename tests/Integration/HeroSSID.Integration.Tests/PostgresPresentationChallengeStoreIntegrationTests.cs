using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit;

namespace HeroSSID.Integration.Tests;

/// <summary>Tests shared PostgreSQL challenge semantics using real independent connections.</summary>
public sealed class PostgresPresentationChallengeStoreIntegrationTests(DatabaseFixture fixture) : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task ChallengeSurvivesStoreReplacementAndConcurrentConsumeSucceedsExactlyOnce()
    {
        await PrepareTableAsync().ConfigureAwait(true);
        await using var dataSource = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var tenant = Guid.NewGuid();
        var first = new PostgresPresentationChallengeStore(dataSource, TimeProvider.System);
        var challenge = first.Issue(tenant, "https://verifier.example/presentation", "did:key:issuer");

        // Separate store objects open independent pooled database connections, as separate replicas would.
        var second = new PostgresPresentationChallengeStore(dataSource, TimeProvider.System);
        Assert.Equal(challenge.TrustedIssuerDid, second.Find(tenant, challenge.Audience, challenge.Nonce)?.TrustedIssuerDid);
        Assert.Null(second.Find(Guid.NewGuid(), challenge.Audience, challenge.Nonce));
        Assert.Null(second.Find(tenant, "https://other.example/presentation", challenge.Nonce));
        Assert.False(second.TryConsume(Guid.NewGuid(), challenge.Audience, challenge.Nonce));
        Assert.False(second.TryConsume(tenant, "https://other.example/presentation", challenge.Nonce));

        var consumers = Enumerable.Range(0, 16)
            .Select(index => Task.Run(() =>
                (index % 2 == 0 ? first : second).TryConsume(tenant, challenge.Audience, challenge.Nonce)));
        var results = await Task.WhenAll(consumers).ConfigureAwait(true);
        Assert.Single(results, success => success);

        // A new store after the first two have gone away must still reject the replay.
        var restarted = new PostgresPresentationChallengeStore(dataSource, TimeProvider.System);
        Assert.Null(restarted.Find(tenant, challenge.Audience, challenge.Nonce));
        Assert.False(restarted.TryConsume(tenant, challenge.Audience, challenge.Nonce));
    }

    [Fact]
    public async Task DistributedCapacityAdmissionCannotExceedLimitUnderConcurrentIssuance()
    {
        await PrepareTableAsync().ConfigureAwait(true);
        await using var dataSource = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var tenant = Guid.NewGuid();
        var clock = new AdjustableClock();
        var first = new PostgresPresentationChallengeStore(dataSource, clock, capacity: 1);
        var second = new PostgresPresentationChallengeStore(dataSource, clock, capacity: 1);

        var admissions = Enumerable.Range(0, 12).Select(index => Task.Run(() =>
        {
            try
            {
                return (index % 2 == 0 ? first : second).Issue(tenant, "verifier", "issuer");
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }));
        var results = await Task.WhenAll(admissions).ConfigureAwait(true);
        var issued = Assert.Single(results, challenge => challenge != null);
        Assert.NotNull(first.Find(tenant, "verifier", issued!.Nonce));
        Assert.Throws<InvalidOperationException>(() => second.Issue(tenant, "verifier", "issuer"));
        Assert.True(second.TryConsume(tenant, "verifier", issued.Nonce));
        // Retained replay tombstones also count. Consumption must not bypass the physical-row ceiling.
        Assert.Throws<InvalidOperationException>(() => first.Issue(tenant, "verifier", "issuer"));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.NotNull(first.Issue(tenant, "verifier", "issuer"));
        Assert.False(second.TryConsume(tenant, "verifier", issued.Nonce));
    }

    [Fact]
    public async Task ExpirationAndValidationAreEnforcedAcrossStoreInstances()
    {
        await PrepareTableAsync().ConfigureAwait(true);
        await using var dataSource = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var clock = new AdjustableClock();
        var tenant = Guid.NewGuid();
        var first = new PostgresPresentationChallengeStore(dataSource, clock, capacity: 1);
        var second = new PostgresPresentationChallengeStore(dataSource, clock, capacity: 1);

        Assert.Throws<ArgumentException>(() => first.Issue(Guid.Empty, "audience", "issuer"));
        Assert.Throws<ArgumentException>(() => first.Issue(tenant, "", "issuer"));
        Assert.Throws<ArgumentException>(() => first.Issue(tenant, "audience", ""));
        Assert.Throws<ArgumentException>(() => first.Issue(tenant, new string('x', 2049), "issuer"));
        Assert.Throws<ArgumentOutOfRangeException>(() => first.Issue(tenant, "audience", "issuer", TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => first.Issue(tenant, "audience", "issuer", TimeSpan.FromMinutes(6)));

        var challenge = first.Issue(tenant, "CaseSensitiveAudience", "did:key:issuer", TimeSpan.FromSeconds(10));
        Assert.Null(second.Find(tenant, "casesensitiveaudience", challenge.Nonce));
        Assert.False(second.TryConsume(tenant, "casesensitiveaudience", challenge.Nonce));
        Assert.NotNull(second.Find(tenant, challenge.Audience, challenge.Nonce));

        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Null(second.Find(tenant, challenge.Audience, challenge.Nonce));
        Assert.False(second.TryConsume(tenant, challenge.Audience, challenge.Nonce));
        Assert.NotEqual(challenge.Nonce, second.Issue(tenant, challenge.Audience, "did:key:issuer").Nonce);
    }

    [Fact]
    public async Task RealIssuerAndHolderProofCanBeVerifiedAcrossIndependentDatabaseScopesOnce()
    {
        await PrepareTableAsync().ConfigureAwait(true);
        await using var dataSource = NpgsqlDataSource.Create(_fixture.ConnectionString);
        var options = new DbContextOptionsBuilder<HeroDbContext>().UseNpgsql(_fixture.ConnectionString).Options;
        await using var signingDb = new HeroDbContext(options);
        await using var verificationDb = new HeroDbContext(options);
        using var provider = new ServiceCollection().AddDataProtection().Services.BuildServiceProvider();
        var encryption = new LocalKeyEncryptionService(provider.GetRequiredService<IDataProtectionProvider>());
        using var limiter = new InMemoryRateLimiter();
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var issuerContext = new TenantContext(Guid.NewGuid());
        var holderContext = new TenantContext(Guid.NewGuid());
        var verifierContext = new TenantContext(Guid.NewGuid());
        var methods = new DidMethodResolver([new DidKeyMethod()]);

        var issuerCreation = new DidCreationService(
            signingDb, encryption, issuerContext, methods, loggerFactory.CreateLogger<DidCreationService>(), limiter);
        var holderCreation = new DidCreationService(
            signingDb, encryption, holderContext, methods, loggerFactory.CreateLogger<DidCreationService>(), limiter);
        using var issuer = await issuerCreation.CreateDidAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        using var holder = await holderCreation.CreateDidAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.NotEqual(issuer.PublicKey, holder.PublicKey);

        var issuance = new CredentialIssuanceService(signingDb, encryption, limiter);
        var original = await issuance.IssueCredentialAsync(
            issuerContext, issuer.Id, holder.Id, "MembershipCredential",
            new Dictionary<string, object> { ["role"] = "member", ["id"] = holder.DidIdentifier },
            DateTimeOffset.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken).ConfigureAwait(true);

        var storeOnIssuerReplica = new PostgresPresentationChallengeStore(dataSource, TimeProvider.System);
        var signing = new VerifiablePresentationService(
            signingDb, new CredentialVerificationService(signingDb, limiter), limiter, encryption,
            storeOnIssuerReplica, TimeProvider.System);
        const string audience = "https://independent-verifier.example/vp";
        var request = signing.CreateChallenge(verifierContext, audience, issuer.DidIdentifier);
        var proof = await signing.CreatePresentationAsync(
            holderContext, original, holder.Id, request, TestContext.Current.CancellationToken).ConfigureAwait(true);

        var storeOnVerifierReplica = new PostgresPresentationChallengeStore(dataSource, TimeProvider.System);
        var verifying = new VerifiablePresentationService(
            verificationDb, new CredentialVerificationService(verificationDb, limiter), limiter,
            encryption, storeOnVerifierReplica, TimeProvider.System);
        var accepted = await verifying.VerifyPresentationAsync(
            verifierContext, proof.PresentationJwt, audience, request.Nonce,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(accepted.IsValid, string.Join(";", accepted.ValidationErrors));
        Assert.Equal(holder.DidIdentifier, accepted.HolderDid);
        Assert.Equal(issuer.DidIdentifier, Assert.Single(accepted.IssuerDids!));

        var replay = await signing.VerifyPresentationAsync(
            verifierContext, proof.PresentationJwt, audience, request.Nonce,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.False(replay.IsValid);
        Assert.Null(replay.DisclosedClaims);
    }

    private async Task PrepareTableAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        await db.Database.ExecuteSqlRawAsync(
            "DELETE FROM presentation_challenges", TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private sealed class TenantContext(Guid tenantId) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenantId;
    }

    private sealed class AdjustableClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
