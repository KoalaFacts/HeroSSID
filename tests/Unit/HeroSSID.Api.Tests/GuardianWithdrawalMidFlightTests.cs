using System.Net;
using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

/// <summary>
/// A valid recovery proof must not disclose a successor when the verifier
/// withdraws its approved guardian enrollment during nonce consumption.
/// The withdrawal is deterministically interleaved with the real signatures.
/// </summary>
public sealed class GuardianWithdrawalMidFlightTests
{
    private const string Audience = "https://verifier.example/issuer-guardian-recovery";

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public async Task MidFlightWithdrawalMustSuppressSuccessor(
        bool hostPinned, bool withdrawDuringConsumption)
    {
        using var previous = NewKey();
        using var successor = NewKey();
        using var guardianOne = NewKey();
        using var guardianTwo = NewKey();
        string previousDid = Did(previous);
        string successorDid = Did(successor);
        string guardianOneDid = Did(guardianOne);
        string guardianTwoDid = Did(guardianTwo);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string enrollmentJwt = IssuerGuardianRecoveryEnrollment.Create(
            previousDid, previous.Export(KeyBlobFormat.RawPrivateKey),
            [guardianOneDid, guardianTwoDid], 2, new Uri(Audience),
            now.AddMinutes(-1), now.AddHours(2));
        string digest = IssuerGuardianRecoveryEnrollment.Fingerprint(enrollmentJwt);
        Guid tenant = Guid.NewGuid();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IssuerGuardianEnrollmentTrust:Registrations:0:TenantId"] = tenant.ToString(),
                ["IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid"] = previousDid,
                ["IssuerGuardianEnrollmentTrust:Registrations:0:Audience"] = Audience,
                ["IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt"] = enrollmentJwt,
                ["IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256"] = digest
            }).Build();
        var registry = new HostPinnedGuardianEnrollmentRegistry(configuration, TimeProvider.System);
        var underlying = new InMemoryPresentationChallengeStore(TimeProvider.System);
        PresentationChallenge challenge = IssuerGuardianRecoveryEnrollment.IssueChallenge(
            underlying, tenant, enrollmentJwt, digest, previousDid, new Uri(Audience),
            TimeProvider.System);
        string proof = IssuerGuardianRecovery.Create(previousDid, successorDid,
            successor.Export(KeyBlobFormat.RawPrivateKey),
            new Dictionary<string, byte[]>
            {
                [guardianOneDid] = guardianOne.Export(KeyBlobFormat.RawPrivateKey),
                [guardianTwoDid] = guardianTwo.Export(KeyBlobFormat.RawPrivateKey)
            }, new Uri(Audience), challenge.Nonce, TimeProvider.System);

        var intercepted = new WithdrawingChallengeStore(underlying, () =>
        {
            if (withdrawDuringConsumption)
            {
                // This occurs only after the real proof has successfully
                // consumed the verifier's one-use challenge.
                configuration["IssuerGuardianEnrollmentTrust:RevokedSha256:0"] = digest;
            }
        });

        var tenantContext = new FixedTenantContext(tenant);
        IResult response = hostPinned
            ? HostPinnedIssuerGuardianRecoveryHttpEndpoints.Verify(
                new VerifyHostPinnedGuardianRecoveryRequest
                {
                    Audience = Audience,
                    TrustedPreviousIssuerDid = previousDid,
                    Nonce = challenge.Nonce,
                    EvidenceJson = proof
                }, registry, intercepted, tenantContext, TimeProvider.System)
            : IssuerGuardianEnrollmentHttpEndpoints.Verify(
                new VerifyExactEnrolledGuardianRecoveryRequest
                {
                    Audience = Audience,
                    TrustedPreviousIssuerDid = previousDid,
                    Nonce = challenge.Nonce,
                    EvidenceJson = proof,
                    SignedEnrollmentJwt = enrollmentJwt,
                    IndependentlyPinnedSha256 = digest
                }, intercepted, tenantContext, registry, TimeProvider.System);

        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var http = new DefaultHttpContext { RequestServices = services };
        using var output = new MemoryStream();
        http.Response.Body = output;
        await response.ExecuteAsync(http).ConfigureAwait(true);
        Assert.Equal((int)HttpStatusCode.OK, http.Response.StatusCode);
        output.Position = 0;
        using var body = await JsonDocument.ParseAsync(output).ConfigureAwait(true);
        Assert.Equal(withdrawDuringConsumption ? "Invalid" : "ValidRecoveryEvidence",
            body.RootElement.GetProperty("status").GetString());
        JsonElement candidate = body.RootElement.GetProperty("successorIssuerDid");
        if (withdrawDuringConsumption)
        {
            Assert.Equal(JsonValueKind.Null, candidate.ValueKind);
            Assert.False(registry.IsAllowedFingerprint(digest));
        }
        else
        {
            Assert.Equal(successorDid, candidate.GetString());
        }
    }

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string Did(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }

    private sealed class FixedTenantContext(Guid tenantId) : ITenantContext
    {
        public Guid GetCurrentTenantId() => tenantId;
    }

    private sealed class WithdrawingChallengeStore(
        IPresentationChallengeStore inner, Action afterConsumption)
        : IPresentationChallengeStore
    {
        public PresentationChallenge Issue(Guid tenantId, string audience,
            string trustedIssuerDid, TimeSpan? lifetime = null) =>
            inner.Issue(tenantId, audience, trustedIssuerDid, lifetime);

        public PresentationChallenge? Find(Guid tenantId, string audience, string nonce) =>
            inner.Find(tenantId, audience, nonce);

        public bool TryConsume(Guid tenantId, string audience, string nonce)
        {
            bool consumed = inner.TryConsume(tenantId, audience, nonce);
            if (consumed)
            {
                afterConsumption();
            }

            return consumed;
        }
    }
}
