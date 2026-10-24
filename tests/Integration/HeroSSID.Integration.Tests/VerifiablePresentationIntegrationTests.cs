using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HeroSSID.Integration.Tests;

/// <summary>PostgreSQL + real protected keys, issuance and full-disclosure presentation verification.</summary>
public sealed class VerifiablePresentationIntegrationTests(DatabaseFixture fixture) : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture = fixture;
    private static readonly IDidMethod[] _didMethods = [new DidKeyMethod()];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FullCredentialFlowPreservesIssuerAcrossTenantsAndRejectsReplayAndRevocation(bool separateHolderTenant)
    {
        var commands = new VerificationCommandCapture();
        var options = new DbContextOptionsBuilder<HeroDbContext>().UseNpgsql(_fixture.ConnectionString).AddInterceptors(commands).Options;
        await using var db = new HeroDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        await db.Database.EnsureCreatedAsync(cancellationToken).ConfigureAwait(true);
        using var provider = new ServiceCollection().AddDataProtection().Services.BuildServiceProvider();
        var encryption = new LocalKeyEncryptionService(provider.GetRequiredService<IDataProtectionProvider>());
        using var limiter = new InMemoryRateLimiter();
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var issuerContext = new TestTenantContext(Guid.NewGuid());
        var holderContext = separateHolderTenant ? new TestTenantContext(Guid.NewGuid()) : issuerContext;
        var verifierContext = new TestTenantContext(Guid.NewGuid());
        var methods = new DidMethodResolver(_didMethods);
        var issuerCreator = new DidCreationService(db, encryption, issuerContext, methods, loggerFactory.CreateLogger<DidCreationService>(), limiter);
        var holderCreator = new DidCreationService(db, encryption, holderContext, methods, loggerFactory.CreateLogger<DidCreationService>(), limiter);
        using var issuer = await issuerCreator.CreateDidAsync(cancellationToken).ConfigureAwait(true);
        using var holder = await holderCreator.CreateDidAsync(cancellationToken).ConfigureAwait(true);
        Assert.NotEqual(issuer.PublicKey, holder.PublicKey);
        var issuance = new CredentialIssuanceService(db, encryption, limiter);
        var original = await issuance.IssueCredentialAsync(issuerContext, issuer.Id, holder.Id, "MembershipCredential",
            new Dictionary<string, object> { ["name"] = "Alice", ["role"] = "member", ["id"] = holder.DidIdentifier },
            DateTimeOffset.UtcNow.AddHours(1), cancellationToken).ConfigureAwait(true);
        var challenges = new InMemoryPresentationChallengeStore(TimeProvider.System);
        var service = new VerifiablePresentationService(db, new CredentialVerificationService(db, limiter), limiter, encryption, challenges, TimeProvider.System);
        const string audience = "https://verifier.example/credentials";
        var challenge = service.CreateChallenge(verifierContext, audience, issuer.DidIdentifier);
        var presentation = await service.CreatePresentationAsync(holderContext, original, holder.Id, challenge, cancellationToken).ConfigureAwait(true);
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation.PresentationJwt));
        Assert.Equal(original, payload.RootElement.GetProperty("vp").GetProperty("verifiableCredential")[0].GetString());
        Assert.Empty(presentation.SelectedDisclosures);
        Assert.Equal(3, presentation.DisclosedClaimNames.Length);

        commands.Commands.Clear();
        var result = await service.VerifyPresentationAsync(verifierContext, presentation.PresentationJwt, audience, challenge.Nonce, cancellationToken).ConfigureAwait(true);
        Assert.True(result.IsValid, string.Join(';', result.ValidationErrors));
        Assert.Equal(issuer.DidIdentifier, Assert.Single(result.IssuerDids!));
        Assert.Equal(holder.DidIdentifier, result.HolderDid);
        Assert.Equal("member", Assert.IsType<JsonElement>(result.DisclosedClaims!["role"]).GetString());
        Assert.NotEmpty(commands.Commands);
        Assert.All(commands.Commands, command => Assert.DoesNotContain("PrivateKey", command, StringComparison.OrdinalIgnoreCase));
        Assert.All(commands.Commands, command => Assert.DoesNotContain("private_key", command, StringComparison.OrdinalIgnoreCase));

        var replay = await service.VerifyPresentationAsync(verifierContext, presentation.PresentationJwt, audience, challenge.Nonce, cancellationToken).ConfigureAwait(true);
        Assert.False(replay.IsValid);
        Assert.Null(replay.DisclosedClaims);
        var secondChallenge = service.CreateChallenge(verifierContext, audience, issuer.DidIdentifier);
        var secondPresentation = await service.CreatePresentationAsync(holderContext, original, holder.Id, secondChallenge, cancellationToken).ConfigureAwait(true);
        var record = await db.VerifiableCredentials.SingleAsync(vc => vc.CredentialJwt == original, cancellationToken).ConfigureAwait(true);
        Assert.Equal(issuerContext.GetCurrentTenantId(), record.TenantId);
        record.Status = "revoked";
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(true);
        var revoked = await service.VerifyPresentationAsync(verifierContext, secondPresentation.PresentationJwt, audience, secondChallenge.Nonce, cancellationToken).ConfigureAwait(true);
        Assert.False(revoked.IsValid);
        Assert.Null(revoked.DisclosedClaims);
        Assert.Null(revoked.HolderDid);
        Assert.Null(revoked.IssuerDids);
    }

    private sealed class TestTenantContext(Guid tenantId) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenantId;
    }

    private sealed class VerificationCommandCapture : DbCommandInterceptor
    {
        public List<string> Commands { get; } = new();

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            Commands.Add(command.CommandText);
            return ValueTask.FromResult(result);
        }
    }
}
