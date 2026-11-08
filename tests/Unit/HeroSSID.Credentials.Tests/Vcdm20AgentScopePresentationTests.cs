using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real issuer, holder and verifier Ed25519 signers are independent. These are
/// one-use cryptographic scope/status gates, NOT agent business authorization.
/// </summary>
public sealed class Vcdm20AgentScopePresentationTests
{
    private const string Audience = "https://verifier.example/agent-requests";
    private const string Action = "invoices.read";
    private static readonly Uri Context = new("https://issuer.example/vocab/agent-scope/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/agent/123");
    private static readonly Uri Recipient = new(Audience);
    private static readonly Uri Resource = new("https://api.example/projects/42");

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _agent = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void ValidIssuerAgentVerifierSignaturesAndFreshStatusReleaseOneScopedActionOnce()
    {
        var (tenant, store, challenge, request) = Request();
        string original = Issue();
        string vp = Present(request, original);
        string status = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Check(vp, request, status, tenant, challenge, store, out var scope));
        Assert.Equal(_agent.Did, scope.GetProperty("id").GetString());
        Assert.Equal(Action, scope.GetProperty("action").GetString());
        Assert.Equal(Resource.AbsoluteUri, scope.GetProperty("resource").GetString());
        Assert.Equal(3, scope.EnumerateObject().Count());

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, status, tenant, challenge, store, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void WrongActionResourceOrAgentPolicyCannotReleaseAnAuthenticProof()
    {
        var (tenant, store, challenge, request) = Request();
        string vp = Present(request, Issue());
        string status = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, status, tenant, challenge, store, out var denied,
                expectedAction: "invoices.write"));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        // Even a genuinely signed but unsuitable scope cannot be reused with
        // different policy after its authentic holder challenge was spent.
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, status, tenant, challenge, store, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        var (tenant2, store2, challenge2, request2) = Request();
        string vp2 = Present(request2, Issue());
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp2, request2, status, tenant2, challenge2, store2,
                out denied, expectedResource: new Uri("https://api.example/projects/43")));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        var (tenant3, store3, challenge3, request3) = Request();
        string vp3 = Present(request3, Issue());
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp3, request3, status, tenant3, challenge3, store3,
                out denied, expectedAgent: NewIdentity().Did));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void RevokedOriginalSpendsNonceAndCannotBeRetriedWithCleanSnapshot()
    {
        var (tenant, store, challenge, request) = Request();
        string original = Issue();
        string vp = Present(request, original);
        string revoked = Snapshot([original]);

        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Check(vp, request, revoked, tenant, challenge, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, Snapshot([]), tenant, challenge, store, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void ForgedHolderSignatureOrWrongVerifierRequestPinNeverSpendAnAuthenticNonce()
    {
        var (tenant, store, challenge, request) = Request();
        string authenticVp = Present(request, Issue());
        string status = Snapshot([]);
        string[] segments = authenticVp.Split('.');
        segments[2] = (segments[2][0] == 'A' ? "B" : "A") + segments[2][1..];
        string forgedVp = string.Join('.', segments);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(forgedVp, request, status, tenant, challenge, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(authenticVp, request, status, tenant, challenge, store,
                out denied, requestPin: new string('0', 64)));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(authenticVp, request, status, tenant, challenge, store,
                out denied, trustedIssuer: NewIdentity().Did));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Check(authenticVp, request, status, tenant, challenge, store, out var scope));
        Assert.Equal(Action, scope.GetProperty("action").GetString());
    }

    [Fact]
    public void GenuineLongLivedGenericIssuerVcCannotBecomeARestrictedAgentScope()
    {
        var (tenant, store, challenge, request) = Request();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _agent.Did, action = Action, resource = Resource.AbsoluteUri
        }));
        var now = _clock.GetUtcNow();
        string longLived = Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuer.Did, _agent.Did, Vcdm20AgentScopeAssertion.CredentialType,
            Context, subject.RootElement, _issuer.Seed,
            now.AddMinutes(-1), now.AddHours(1), CredentialId, Recipient);
        string vp = Present(request, longLived);
        string status = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, status, tenant, challenge, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, status, tenant, challenge, store, out denied));
    }

    private (Guid Tenant, InMemoryPresentationChallengeStore Store,
        PresentationChallenge Challenge, string Request) Request()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        PresentationChallenge challenge = store.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge with
            {
                CredentialType = Vcdm20AgentScopeAssertion.CredentialType,
                SubjectContextUri = Context
            },
            _verifier.Did, _verifier.Seed, _clock);
        return (tenant, store, challenge, signedRequest);
    }

    private string Issue()
    {
        var now = _clock.GetUtcNow();
        return Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Context, CredentialId,
            Recipient, Resource, Action, _issuer.Seed,
            now.AddSeconds(-5), now.AddMinutes(5));
    }

    private string Present(string request, string original) =>
        Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
            request, _verifier.Did, Audience, original,
            Vcdm20AgentScopeAssertion.CredentialType, Context,
            CredentialId, Recipient, _agent.Did, _agent.Seed, _clock);

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(_issuer.Did, revoked, _issuer.Seed,
            DateTimeOffset.FromUnixTimeSeconds(_clock.GetUtcNow().ToUnixTimeSeconds()), _clock);

    private Vcdm20RevocationCheckResult Check(
        string vp, string request, string snapshot, Guid tenant,
        PresentationChallenge challenge, InMemoryPresentationChallengeStore store,
        out JsonElement scope, string? expectedAction = null, Uri? expectedResource = null,
        string? expectedAgent = null, string? requestPin = null, string? trustedIssuer = null) =>
        Vcdm20AgentScopePresentation.CheckWithIssuerStatus(
            vp, request, requestPin ?? Digest(request), _verifier.Did,
            snapshot, tenant, Audience, challenge.Nonce,
            trustedIssuer ?? _issuer.Did, expectedAgent ?? _agent.Did,
            Context, CredentialId, Recipient, expectedResource ?? Resource,
            expectedAction ?? Action, DateTimeOffset.UnixEpoch, store,
            _clock, out scope);

    private static string Digest(string request) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request)));

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
