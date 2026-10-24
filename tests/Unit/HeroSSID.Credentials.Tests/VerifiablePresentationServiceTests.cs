using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>Real Ed25519 regression tests, including holder-signed malicious envelopes.</summary>
public sealed class VerifiablePresentationServiceTests : IDisposable
{
    private const string Audience = "https://verifier.example/credentials";
    private const string IssuerDid = "did:web:issuer.example";
    private const string HolderDid = "did:web:holder.example";
    private const string VpHeader = "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}";
    private static readonly string[] _malformedSubject = ["Alice"];
    private static readonly string[] _nameClaims = ["name"];
    private static readonly byte[] _invalidUtf8 = [0xc3, 0x28];
    private readonly DbContextOptions<HeroDbContext> _options;
    private readonly HeroDbContext _db;
    private readonly InMemoryRateLimiter _rateLimiter = new(maxOperations: 1000);
    private readonly TestTenantContext _issuerContext = new(Guid.NewGuid());
    private readonly TestTenantContext _holderContext = new(Guid.NewGuid());
    private readonly TestTenantContext _verifierContext = new(Guid.NewGuid());
    private readonly TestTimeProvider _clock = new();
    private readonly InMemoryPresentationChallengeStore _challenges;
    private readonly DidEntity _issuer;
    private readonly DidEntity _holder;
    private readonly byte[] _issuerKey;
    private readonly byte[] _holderKey;

    public VerifiablePresentationServiceTests()
    {
        _options = new DbContextOptionsBuilder<HeroDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        _db = new HeroDbContext(_options);
        (_issuer, _issuerKey) = CreateIdentity(_issuerContext, IssuerDid);
        (_holder, _holderKey) = CreateIdentity(_holderContext, HolderDid);
        _db.Dids.AddRange(_issuer, _holder);
        _db.SaveChanges();
        _challenges = new InMemoryPresentationChallengeStore(_clock);
    }

    [Fact]
    public async Task ThreeTenantFlowPreservesOriginalIssuerAndFullCredential()
    {
        var service = CreateService();
        var original = CreateCredential();
        var challenge = NewChallenge();
        var presentation = await service.CreatePresentationAsync(_holderContext, original, _holder.Id, challenge).ConfigureAwait(true);
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation.PresentationJwt));
        Assert.Equal(original, payload.RootElement.GetProperty("vp").GetProperty("verifiableCredential")[0].GetString());
        Assert.Empty(presentation.SelectedDisclosures);
        Assert.Contains("name", presentation.DisclosedClaimNames);
        Assert.Contains("role", presentation.DisclosedClaimNames);
        Assert.NotEqual(_issuer.PublicKeyEd25519, _holder.PublicKeyEd25519);

        var result = await service.VerifyPresentationAsync(_verifierContext, presentation.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true);

        Assert.True(result.IsValid, string.Join(';', result.ValidationErrors));
        Assert.Equal(HolderDid, result.HolderDid);
        Assert.Equal(IssuerDid, Assert.Single(result.IssuerDids!));
        Assert.Equal("Alice", Assert.IsType<JsonElement>(result.DisclosedClaims!["name"]).GetString());
        Assert.Equal("member", Assert.IsType<JsonElement>(result.DisclosedClaims["role"]).GetString());
        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, presentation.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true));
    }

    [Fact]
    public async Task ThreeTenantFlowUsesIndependentRequesterQuotas()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = CreateService(rateLimiter: limiter);
        var original = CreateCredential();
        var challenge = NewChallenge();

        var presentation = await service.CreatePresentationAsync(_holderContext, original, _holder.Id, challenge).ConfigureAwait(true);
        var result = await service.VerifyPresentationAsync(_verifierContext, presentation.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true);

        Assert.True(result.IsValid);
        var issuerResult = await new CredentialVerificationService(_db, limiter).VerifyCredentialAsync(_issuerContext, original).ConfigureAwait(true);
        Assert.True(issuerResult.IsValid);
        Assert.False(await limiter.IsAllowedAsync(_holderContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.False(await limiter.IsAllowedAsync(_verifierContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
    }

    [Fact]
    public async Task InvalidPresentationCreationAlsoConsumesCreationQuota()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = CreateService(rateLimiter: limiter);
        var forged = CreateCredential(signingKey: _holderKey);
        var challenge = NewChallenge();

        await Assert.ThrowsAsync<ArgumentException>(() => service.CreatePresentationAsync(
            _holderContext, forged, _holder.Id, challenge)).ConfigureAwait(true);

        Assert.False(await limiter.IsAllowedAsync(
            _holderContext.GetCurrentTenantId(), "PRESENTATION_CREATE").ConfigureAwait(true));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreatePresentationAsync(
            _holderContext, forged, _holder.Id, challenge)).ConfigureAwait(true);
    }

    [Fact]
    public async Task ForgedCreationExhaustsHolderQuotaWithoutSpendingIssuerQuota()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = CreateService(rateLimiter: limiter);
        var forged = CreateCredential(signingKey: _holderKey);
        var challenge = NewChallenge();

        await Assert.ThrowsAsync<ArgumentException>(() => service.CreatePresentationAsync(
            _holderContext, forged, _holder.Id, challenge)).ConfigureAwait(true);

        var legitimate = await new CredentialVerificationService(_db, limiter).VerifyCredentialAsync(_issuerContext, CreateCredential()).ConfigureAwait(true);
        Assert.True(legitimate.IsValid);
        Assert.False(await limiter.IsAllowedAsync(_holderContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.IsAllowedAsync(_verifierContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreatePresentationAsync(
            _holderContext, forged, _holder.Id, challenge)).ConfigureAwait(true);
    }

    [Fact]
    public async Task ForgedPresentationExhaustsVerifierQuotaWithoutSpendingIssuerQuota()
    {
        using var limiter = new InMemoryRateLimiter(maxOperations: 1);
        var service = CreateService(rateLimiter: limiter);
        var challenge = NewChallenge();
        var forged = CreateEnvelope(CreateCredential(signingKey: _holderKey), challenge);

        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, forged, Audience, challenge.Nonce).ConfigureAwait(true));
        Assert.NotNull(_challenges.Find(_verifierContext.GetCurrentTenantId(), Audience, challenge.Nonce));

        var legitimate = await new CredentialVerificationService(_db, limiter).VerifyCredentialAsync(_issuerContext, CreateCredential()).ConfigureAwait(true);
        Assert.True(legitimate.IsValid);
        Assert.False(await limiter.IsAllowedAsync(_verifierContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
        Assert.True(await limiter.IsAllowedAsync(_holderContext.GetCurrentTenantId(), "CREDENTIAL_VERIFY").ConfigureAwait(true));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.VerifyPresentationAsync(
            _verifierContext, forged, Audience, challenge.Nonce)).ConfigureAwait(true);
    }

    [Fact]
    public async Task SecurityRegressionForgedIssuerCredentialCannotBecomeValidPresentation()
    {
        var challenge = NewChallenge();
        var forged = CreateCredential(signingKey: _holderKey);
        // An attacker bypasses the creation service and signs a perfectly valid outer holder proof.
        AssertInvalid(await VerifyAsync(CreateEnvelope(forged, challenge), challenge).ConfigureAwait(true));
        Assert.True((await VerifyAsync(CreateEnvelope(CreateCredential(), challenge), challenge).ConfigureAwait(true)).IsValid);
    }

    [Fact]
    public async Task SecurityRegressionCredentialForAnotherHolderCannotBecomeValidPresentation()
    {
        var challenge = NewChallenge();
        var unrelated = CreateCredential(payload => payload["sub"] = "did:web:someone-else.example");
        AssertInvalid(await VerifyAsync(CreateEnvelope(unrelated, challenge), challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task SecurityRegressionAlternateEncodingCannotBypassRevocation()
    {
        var original = CreateCredential();
        await RegisterCredentialAsync(original, "revoked").ConfigureAwait(true);
        var credentialVerifier = new CredentialVerificationService(_db, _rateLimiter);
        var result = await credentialVerifier.VerifyCredentialAsync(_issuerContext, original + "==").ConfigureAwait(true);
        Assert.False(result.IsValid);
        var challenge = NewChallenge();
        AssertInvalid(await VerifyAsync(CreateEnvelope(original + "==", challenge), challenge).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("future-iat")]
    [InlineData("missing-iat")]
    [InlineData("future-nbf")]
    [InlineData("expired")]
    [InlineData("subject-id-conflict")]
    [InlineData("subject-not-object")]
    [InlineData("unknown-issuer")]
    public async Task InvalidOriginalCredentialIsRejectedEvenWithValidHolderSignature(string defect)
    {
        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        var original = CreateCredential(payload =>
        {
            switch (defect)
            {
                case "future-iat": payload["iat"] = now + 60; break;
                case "missing-iat": payload.Remove("iat"); break;
                case "future-nbf": payload["nbf"] = now + 60; break;
                case "expired": payload["exp"] = now - 1; break;
                case "subject-id-conflict": payload["vc"] = new { credentialSubject = new { id = "did:web:another.example", name = "Alice" } }; break;
                case "subject-not-object": payload["vc"] = new { credentialSubject = _malformedSubject }; break;
                case "unknown-issuer": payload["iss"] = "did:web:untrusted.example"; break;
            }
        });
        var challenge = NewChallenge();
        AssertInvalid(await VerifyAsync(CreateEnvelope(original, challenge), challenge).ConfigureAwait(true));
        Assert.NotNull(_challenges.Find(_verifierContext.GetCurrentTenantId(), Audience, challenge.Nonce));
    }

    [Fact]
    public async Task CreationRejectsForgedCredentialAndWrongTenantBeforeDecrypting()
    {
        var encryption = new RejectKeyAccess();
        var service = CreateService(encryption: encryption);
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreatePresentationAsync(
            _holderContext, CreateCredential(signingKey: _holderKey), _holder.Id, NewChallenge())).ConfigureAwait(true);
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreatePresentationAsync(
            _issuerContext, CreateCredential(), _holder.Id, NewChallenge())).ConfigureAwait(true);
        Assert.Equal(0, encryption.DecryptionAttempts);
    }

    [Fact]
    public async Task VerificationRequiresNoPrivateKeyAccess()
    {
        var encryption = new RejectKeyAccess();
        var challenge = NewChallenge();
        var result = await CreateService(encryption: encryption).VerifyPresentationAsync(
            _verifierContext, CreateEnvelope(CreateCredential(), challenge), Audience, challenge.Nonce).ConfigureAwait(true);
        Assert.True(result.IsValid);
        Assert.Equal(0, encryption.DecryptionAttempts);
    }

    [Fact]
    public async Task HolderKeyIsClearedAfterCreation()
    {
        var encryption = new CopyKeyEncryption();
        await CreateService(encryption: encryption).CreatePresentationAsync(_holderContext, CreateCredential(), _holder.Id, NewChallenge()).ConfigureAwait(true);
        Assert.NotNull(encryption.LastDecrypted);
        Assert.All(encryption.LastDecrypted!, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public async Task WrongAudienceNonceTenantAndUnissuedChallengeDoNotConsumeValidRequest()
    {
        var service = CreateService();
        var challenge = NewChallenge();
        var presentation = CreateEnvelope(CreateCredential(), challenge);
        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, presentation, "https://other.example", challenge.Nonce).ConfigureAwait(true));
        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, presentation, Audience, new string('A', 43)).ConfigureAwait(true));
        AssertInvalid(await service.VerifyPresentationAsync(_holderContext, presentation, Audience, challenge.Nonce).ConfigureAwait(true));
        var invented = challenge with { Nonce = new string('B', 43) };
        AssertInvalid(await VerifyAsync(CreateEnvelope(CreateCredential(), invented), invented).ConfigureAwait(true));
        Assert.True((await VerifyAsync(presentation, challenge).ConfigureAwait(true)).IsValid);
    }

    [Fact]
    public async Task VerifierMustExplicitlyTrustCredentialIssuer()
    {
        var challenge = CreateService().CreateChallenge(_verifierContext, Audience, HolderDid);
        AssertInvalid(await VerifyAsync(CreateEnvelope(CreateCredential(), challenge), challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task WrongHolderSignatureDoesNotConsumeChallenge()
    {
        var challenge = NewChallenge();
        AssertInvalid(await VerifyAsync(CreateEnvelope(CreateCredential(), challenge, signingKey: _issuerKey), challenge).ConfigureAwait(true));
        Assert.True((await VerifyAsync(CreateEnvelope(CreateCredential(), challenge), challenge).ConfigureAwait(true)).IsValid);
    }

    [Theory]
    [InlineData("holder", "deactivated")]
    [InlineData("issuer", "deactivated")]
    [InlineData("holder", "unknown")]
    [InlineData("issuer", "unknown")]
    public async Task IdentityStateIsRecheckedAfterPresentationCreation(string identity, string status)
    {
        var challenge = NewChallenge();
        var presentation = await CreateService().CreatePresentationAsync(_holderContext, CreateCredential(), _holder.Id, challenge).ConfigureAwait(true);
        (identity == "holder" ? _holder : _issuer).Status = status;
        await _db.SaveChangesAsync().ConfigureAwait(true);
        AssertInvalid(await VerifyAsync(presentation.PresentationJwt, challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task RevocationAfterCreationIsRejected()
    {
        var original = CreateCredential();
        var record = await RegisterCredentialAsync(original, "active").ConfigureAwait(true);
        var challenge = NewChallenge();
        var presentation = await CreateService().CreatePresentationAsync(_holderContext, original, _holder.Id, challenge).ConfigureAwait(true);
        record.Status = "revoked";
        await _db.SaveChangesAsync().ConfigureAwait(true);
        AssertInvalid(await VerifyAsync(presentation.PresentationJwt, challenge).ConfigureAwait(true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnyRevokedDuplicateRecordMakesTheSameCredentialInvalid(bool revokedFirst)
    {
        var original = CreateCredential();
        await RegisterCredentialAsync(original, revokedFirst ? "revoked" : "active").ConfigureAwait(true);
        await RegisterCredentialAsync(original, revokedFirst ? "active" : "revoked").ConfigureAwait(true);
        var challenge = NewChallenge();
        Assert.False((await new CredentialVerificationService(_db, _rateLimiter)
            .VerifyCredentialAsync(_issuerContext, original).ConfigureAwait(true)).IsValid);
        AssertInvalid(await VerifyAsync(CreateEnvelope(original, challenge), challenge).ConfigureAwait(true));
        Assert.NotNull(_challenges.Find(_verifierContext.GetCurrentTenantId(), Audience, challenge.Nonce));
    }

    [Theory]
    [InlineData("future-iat")]
    [InlineData("expired")]
    [InlineData("too-long")]
    [InlineData("outlives-challenge")]
    [InlineData("wrong-audience")]
    [InlineData("wrong-nonce")]
    [InlineData("iat-string")]
    [InlineData("multiple-credentials")]
    [InlineData("extra-field")]
    public async Task HolderSignedMalformedOrUnboundEnvelopeIsRejected(string defect)
    {
        var challenge = NewChallenge();
        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        var original = CreateCredential();
        var presentation = CreateEnvelope(original, challenge, payload =>
        {
            switch (defect)
            {
                case "future-iat": payload["iat"] = now + 10; break;
                case "expired": payload["exp"] = now; break;
                case "too-long": payload["iat"] = now - 600; break;
                case "outlives-challenge": payload["exp"] = challenge.ExpiresAt.ToUnixTimeSeconds() + 1; break;
                case "wrong-audience": payload["aud"] = "https://other.example"; break;
                case "wrong-nonce": payload["nonce"] = new string('C', 43); break;
                case "iat-string": payload["iat"] = "123"; break;
                case "multiple-credentials": payload["vp"] = new { verifiableCredential = new[] { original, original } }; break;
                case "extra-field": payload["jku"] = "https://attacker.example/keys"; break;
            }
        });
        AssertInvalid(await VerifyAsync(presentation, challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task DuplicateFieldsWrongHeaderMalformedJsonAndOversizedTokensFailClosed()
    {
        var challenge = NewChallenge();
        var original = CreateEnvelope(CreateCredential(), challenge);
        var payload = Ed25519JwtSigner.ExtractPayload(original);
        var duplicate = "{\"aud\":\"https://attacker.example\"," + payload[1..];
        var invalidTokens = new[]
        {
            Ed25519JwtSigner.CreateSignedJwt(VpHeader, duplicate, _holderKey),
            Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}", payload, _holderKey),
            Ed25519JwtSigner.CreateSignedJwt(VpHeader, "[]", _holderKey),
            Ed25519JwtSigner.CreateSignedJwt(VpHeader, "{", _holderKey),
            original + "==", "not-a-token", new string('A', 131_073)
        };
        foreach (var invalid in invalidTokens)
        {
            AssertInvalid(await VerifyAsync(invalid, challenge).ConfigureAwait(true));
        }
        Assert.True((await VerifyAsync(original, challenge).ConfigureAwait(true)).IsValid);
    }

    [Theory]
    [InlineData("holder")]
    [InlineData("issuer")]
    public async Task MalformedEnrolledPublicKeyReturnsInvalidWithoutThrowing(string identity)
    {
        var challenge = NewChallenge();
        var presentation = CreateEnvelope(CreateCredential(), challenge);
        (identity == "holder" ? _holder : _issuer).PublicKeyEd25519 = new byte[1];
        await _db.SaveChangesAsync().ConfigureAwait(true);
        AssertInvalid(await VerifyAsync(presentation, challenge).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("property")]
    [InlineData("holder")]
    [InlineData("credential-claim")]
    [InlineData("header-property")]
    public async Task MalformedUnicodeFailsClosedWithoutConsumingChallenge(string defect)
    {
        var challenge = NewChallenge();
        var original = CreateCredential();
        var envelope = CreateEnvelope(original, challenge);
        var payload = Ed25519JwtSigner.ExtractPayload(envelope);
        var malformed = defect switch
        {
            "property" => Ed25519JwtSigner.CreateSignedJwt(VpHeader, "{\"\\uD800\":1}", _holderKey),
            "holder" => Ed25519JwtSigner.CreateSignedJwt(VpHeader, payload.Replace(HolderDid, "\\uD800", StringComparison.Ordinal), _holderKey),
            "header-property" => Ed25519JwtSigner.CreateSignedJwt("{\"\\uD800\":\"EdDSA\",\"typ\":\"vp+jwt\"}", payload, _holderKey),
            _ => CreateEnvelope(Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
                Ed25519JwtSigner.ExtractPayload(original).Replace("Alice", "\\uD800", StringComparison.Ordinal), _issuerKey), challenge)
        };

        AssertInvalid(await VerifyAsync(malformed, challenge).ConfigureAwait(true));
        Assert.True((await VerifyAsync(envelope, challenge).ConfigureAwait(true)).IsValid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InvalidUtf8FailsClosedWithoutConsumingChallenge(bool propertyName)
    {
        var challenge = NewChallenge();
        var prefix = propertyName ? "{\"" : "{\"iss\":\"";
        var suffix = propertyName ? "\":1}" : "\"}";
        var invalidPayload = Encoding.UTF8.GetBytes(prefix).Concat(_invalidUtf8).Concat(Encoding.UTF8.GetBytes(suffix)).ToArray();
        var token = Base64UrlEncoder.Encode(VpHeader) + "." + Base64UrlEncoder.Encode(invalidPayload) + "." + Base64UrlEncoder.Encode(new byte[64]);
        AssertInvalid(await VerifyAsync(token, challenge).ConfigureAwait(true));
        Assert.True((await VerifyAsync(CreateEnvelope(CreateCredential(), challenge), challenge).ConfigureAwait(true)).IsValid);
    }

    [Fact]
    public async Task CredentialExpiryBoundsCreatedAndManuallySignedPresentation()
    {
        var expiry = _clock.GetUtcNow().AddSeconds(30).ToUnixTimeSeconds();
        var original = CreateCredential(payload => payload["exp"] = expiry);
        var challenge = NewChallenge();
        var created = await CreateService().CreatePresentationAsync(_holderContext, original, _holder.Id, challenge).ConfigureAwait(true);
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(created.PresentationJwt));
        Assert.Equal(expiry, payload.RootElement.GetProperty("exp").GetInt64());
        AssertInvalid(await VerifyAsync(CreateEnvelope(original, challenge), challenge).ConfigureAwait(true));
        Assert.True((await VerifyAsync(created.PresentationJwt, challenge).ConfigureAwait(true)).IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiryDuringCredentialVerificationIsRecheckedBeforeAcceptance(bool expireChallenge)
    {
        var original = expireChallenge ? CreateCredential() : CreateCredential(payload => payload["exp"] = _clock.GetUtcNow().AddSeconds(20).ToUnixTimeSeconds());
        var challenge = NewChallenge();
        var created = await CreateService().CreatePresentationAsync(_holderContext, original, _holder.Id, challenge).ConfigureAwait(true);
        var advancingVerifier = new AdvancingCredentialVerifier(new CredentialVerificationService(_db, _rateLimiter),
            () => _clock.Advance(expireChallenge ? TimeSpan.FromMinutes(3) : TimeSpan.FromSeconds(30)));
        var service = new VerifiablePresentationService(_db, advancingVerifier, _rateLimiter, new RejectKeyAccess(), _challenges, _clock);

        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, created.PresentationJwt, Audience, challenge.Nonce).ConfigureAwait(true));
        if (!expireChallenge)
        {
            Assert.NotNull(_challenges.Find(_verifierContext.GetCurrentTenantId(), Audience, challenge.Nonce));
        }
    }

    [Fact]
    public async Task NestedDuplicateCredentialClaimsAreRejected()
    {
        var original = CreateCredential();
        var payload = Ed25519JwtSigner.ExtractPayload(original).Replace("\"name\":", "\"name\":\"Mallory\",\"name\":", StringComparison.Ordinal);
        var ambiguous = Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}", payload, _issuerKey);
        var challenge = NewChallenge();
        AssertInvalid(await VerifyAsync(CreateEnvelope(ambiguous, challenge), challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task ExpiredChallengeAndRestartedStoreRejectOutstandingPresentation()
    {
        var challenge = NewChallenge();
        var presentation = CreateEnvelope(CreateCredential(), challenge);
        var restarted = new InMemoryPresentationChallengeStore(_clock);
        var result = await CreateService(challenges: restarted).VerifyPresentationAsync(_verifierContext, presentation, Audience, challenge.Nonce).ConfigureAwait(true);
        AssertInvalid(result);
        _clock.Advance(TimeSpan.FromMinutes(3));
        AssertInvalid(await VerifyAsync(presentation, challenge).ConfigureAwait(true));
    }

    [Fact]
    public async Task ConcurrentVerificationAcrossDatabaseScopesAcceptsExactlyOnce()
    {
        var challenge = NewChallenge();
        var presentation = CreateEnvelope(CreateCredential(), challenge);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            using var db = new HeroDbContext(_options);
            var service = CreateService(db);
            await start.Task.ConfigureAwait(false);
            return await service.VerifyPresentationAsync(_verifierContext, presentation, Audience, challenge.Nonce).ConfigureAwait(false);
        })).ToArray();
        start.SetResult();
        var results = await Task.WhenAll(tasks).ConfigureAwait(true);
        Assert.Single(results, result => result.IsValid);
        Assert.All(results.Where(result => !result.IsValid), AssertInvalid);
    }

    [Fact]
    public async Task LegacyChallengeLessAndSelectiveDisclosureCallsFailClosed()
    {
        var service = CreateService();
        await Assert.ThrowsAsync<NotSupportedException>(() => service.CreatePresentationAsync(
            _holderContext, CreateCredential(), _nameClaims, _holder.Id, Audience)).ConfigureAwait(true);
        await Assert.ThrowsAsync<NotSupportedException>(() => service.CreatePresentationAsync(
            _holderContext, CreateCredential(), null, _holder.Id, Audience)).ConfigureAwait(true);
        AssertInvalid(await service.VerifyPresentationAsync(_verifierContext, "legacy.jwt.presentation", Array.Empty<string>()).ConfigureAwait(true));
    }

    private VerifiablePresentationService CreateService(HeroDbContext? db = null, IKeyEncryptionService? encryption = null, IPresentationChallengeStore? challenges = null, IRateLimiter? rateLimiter = null)
    {
        var context = db ?? _db;
        var limiter = rateLimiter ?? _rateLimiter;
        return new VerifiablePresentationService(context, new CredentialVerificationService(context, limiter), limiter,
            encryption ?? new CopyKeyEncryption(), challenges ?? _challenges, _clock);
    }

    private PresentationChallenge NewChallenge() => CreateService().CreateChallenge(_verifierContext, Audience, IssuerDid);

    private Task<PresentationVerificationResult> VerifyAsync(string presentation, PresentationChallenge challenge) =>
        CreateService().VerifyPresentationAsync(_verifierContext, presentation, Audience, challenge.Nonce);

    private string CreateCredential(Action<Dictionary<string, object?>>? edit = null, byte[]? signingKey = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = IssuerDid, ["sub"] = HolderDid,
            ["iat"] = _clock.GetUtcNow().ToUnixTimeSeconds() - 1,
            ["exp"] = _clock.GetUtcNow().AddHours(1).ToUnixTimeSeconds(),
            ["vc"] = new { credentialSubject = new { id = HolderDid, name = "Alice", role = "member" } }
        };
        edit?.Invoke(payload);
        return Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}", JsonSerializer.Serialize(payload), signingKey ?? _issuerKey);
    }

    private string CreateEnvelope(string credential, PresentationChallenge challenge, Action<Dictionary<string, object?>>? edit = null, byte[]? signingKey = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = HolderDid, ["aud"] = challenge.Audience, ["nonce"] = challenge.Nonce,
            ["iat"] = _clock.GetUtcNow().ToUnixTimeSeconds(), ["exp"] = challenge.ExpiresAt.ToUnixTimeSeconds(),
            ["vp"] = new { verifiableCredential = new[] { credential } }
        };
        edit?.Invoke(payload);
        return Ed25519JwtSigner.CreateSignedJwt(VpHeader, JsonSerializer.Serialize(payload), signingKey ?? _holderKey);
    }

    private async Task<VerifiableCredentialEntity> RegisterCredentialAsync(string jwt, string status)
    {
        var credential = new VerifiableCredentialEntity
        {
            Id = Guid.NewGuid(), TenantId = _issuerContext.GetCurrentTenantId(), IssuerDidId = _issuer.Id,
            HolderDidId = _holder.Id, CredentialType = "MembershipCredential", CredentialJwt = jwt, Status = status
        };
        _db.VerifiableCredentials.Add(credential);
        await _db.SaveChangesAsync().ConfigureAwait(true);
        return credential;
    }

    private static (DidEntity Identity, byte[] PrivateKey) CreateIdentity(ITenantContext context, string did)
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var privateKey = key.Export(KeyBlobFormat.RawPrivateKey)[..32];
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        return (new DidEntity
        {
            Id = Guid.NewGuid(), TenantId = context.GetCurrentTenantId(), DidIdentifier = did,
            PublicKeyEd25519 = publicKey, KeyFingerprint = SHA256.HashData(publicKey),
            PrivateKeyEd25519Encrypted = privateKey.ToArray(), DidDocumentJson = "{}", Status = "active", CreatedAt = DateTimeOffset.UtcNow
        }, privateKey);
    }

    private static void AssertInvalid(PresentationVerificationResult result)
    {
        Assert.False(result.IsValid);
        Assert.NotEqual(PresentationVerificationStatus.Valid, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
        Assert.Null(result.DisclosedClaims);
        Assert.Null(result.HolderDid);
        Assert.Null(result.IssuerDids);
    }

    public void Dispose()
    {
        _db.Dispose();
        _rateLimiter.Dispose();
        CryptographicOperations.ZeroMemory(_issuerKey);
        CryptographicOperations.ZeroMemory(_holderKey);
    }

    private sealed class TestTenantContext(Guid tenantId) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenantId;
    }

    private sealed class TestTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class CopyKeyEncryption : IKeyEncryptionService
    {
        public byte[]? LastDecrypted { get; private set; }
        public byte[] Encrypt(byte[] plaintext) => plaintext.ToArray();
        public byte[] Decrypt(byte[] ciphertext) => LastDecrypted = ciphertext.ToArray();
        public string EncryptString(string plaintext) => plaintext;
        public string DecryptString(string ciphertext) => ciphertext;
    }

    private sealed class RejectKeyAccess : IKeyEncryptionService
    {
        public int DecryptionAttempts { get; private set; }
        public byte[] Encrypt(byte[] plaintext) => throw new NotSupportedException();
        public byte[] Decrypt(byte[] ciphertext)
        {
            DecryptionAttempts++;
            throw new InvalidOperationException("Verification must not decrypt private keys.");
        }
        public string EncryptString(string plaintext) => throw new NotSupportedException();
        public string DecryptString(string ciphertext) => throw new NotSupportedException();
    }

    private sealed class AdvancingCredentialVerifier(ICredentialVerificationService inner, Action advance) : ICredentialVerificationService
    {
        public async Task<CredentialVerificationResult> VerifyCredentialAsync(ITenantContext tenantContext, string credentialJwt, CancellationToken cancellationToken = default)
        {
            var result = await inner.VerifyCredentialAsync(tenantContext, credentialJwt, cancellationToken).ConfigureAwait(false);
            advance();
            return result;
        }

        public async Task<CredentialVerificationResult> VerifyCredentialFromIssuerAsync(ITenantContext requesterContext, Guid issuerTenantId, string credentialJwt, CancellationToken cancellationToken = default)
        {
            var result = await inner.VerifyCredentialFromIssuerAsync(requesterContext, issuerTenantId, credentialJwt, cancellationToken).ConfigureAwait(false);
            advance();
            return result;
        }
    }
}
