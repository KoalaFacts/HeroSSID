using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real Ed25519 issuer assertions bound to one relying party, one agent,
/// one resource and one narrowly named action. No holder possession or
/// operational authorization is inferred from these credentials.
/// </summary>
public sealed class Vcdm20AgentScopeAssertionTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary =
        new("https://issuer.example/vocab/agent-scope/v1");
    private static readonly Uri CredentialId =
        new("https://issuer.example/credentials/delegation/123");
    private static readonly Uri Recipient =
        new("https://verifier.example/agent-requests");
    private static readonly Uri Resource =
        new("https://api.example/projects/project-42");
    private const string Action = "invoices.read";

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _agent = NewIdentity();
    private readonly (byte[] Seed, string Did) _otherIssuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _otherAgent = NewIdentity();

    [Fact]
    public void AnIssuerCanAttestOneShortLivedAgentScopeForAnIndependentlyPinnedVerifier()
    {
        string original = Issue();
        Assert.True(Check(original, out JsonElement scope));
        Assert.Equal(_agent.Did, scope.GetProperty("id").GetString());
        Assert.Equal(Action, scope.GetProperty("action").GetString());
        Assert.Equal(Resource.AbsoluteUri, scope.GetProperty("resource").GetString());
        Assert.Equal(3, scope.EnumerateObject().Count());

        // This profile has a signed recipient; the audience-free VC2 verifier
        // must not silently treat it as a legacy six-member credential.
        Assert.False(Vcdm20JoseCredential.TryVerify(
            original, _issuer.Did, _agent.Did,
            Vcdm20AgentScopeAssertion.CredentialType, Vocabulary,
            Now, out _));
    }

    [Fact]
    public void DifferentRealIssuerAgentRecipientResourceActionOrIdNeverReleaseScope()
    {
        string original = Issue();
        Assert.False(Check(original, out JsonElement denied, trustedIssuer: _otherIssuer.Did));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(Check(original, out denied, agent: _otherAgent.Did));
        Assert.False(Check(original, out denied, recipient: new Uri("https://attacker.example/agent-requests")));
        Assert.False(Check(original, out denied, resource: new Uri("https://api.example/projects/project-43")));
        Assert.False(Check(original, out denied, action: "invoices.write"));
        Assert.False(Check(original, out denied, credentialId: new Uri("https://issuer.example/credentials/delegation/456")));
        Assert.False(Check(original, out denied, context: new Uri("https://issuer.example/vocab/other")));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.True(Check(original, out _));
    }

    [Fact]
    public void ForgedSignatureAndWrongIssuerPrivateKeyCannotIssueOrVerify()
    {
        Assert.Throws<ArgumentException>(() => Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Vocabulary, CredentialId, Recipient,
            Resource, Action, _otherIssuer.Seed, Now.AddSeconds(-5), Now.AddMinutes(5)));

        string original = Issue();
        string[] segments = original.Split('.');
        string payload = Ed25519JwtSigner.ExtractPayload(original);
        Assert.Contains(Action, payload, StringComparison.Ordinal);
        segments[1] = Base64UrlEncoder.Encode(payload.Replace(
            Action, "invoices.write", StringComparison.Ordinal));
        string forged = string.Join('.', segments);
        Assert.False(Check(forged, out JsonElement denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        string honestlySignedForDifferentRecipient = Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Vocabulary, CredentialId,
            new Uri("https://other-verifier.example/agent-requests"),
            Resource, Action, _issuer.Seed, Now.AddSeconds(-5), Now.AddMinutes(5));
        Assert.False(Check(honestlySignedForDifferentRecipient, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void ShortLifetimeAndExactScopedStringsAreMandatoryEvenWithAuthenticIssuerSignature()
    {
        Assert.False(Check(Issue(), out JsonElement denied, now: Now.AddMinutes(7)));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Throws<ArgumentException>(() => Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Vocabulary, CredentialId, Recipient,
            Resource, Action, _issuer.Seed, Now.AddSeconds(-5), Now.AddHours(1)));
        Assert.Throws<ArgumentException>(() => Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Vocabulary, CredentialId, Recipient,
            Resource, "*", _issuer.Seed, Now.AddSeconds(-5), Now.AddMinutes(5)));
        Assert.Throws<ArgumentException>(() => Vcdm20AgentScopeAssertion.Create(
            _issuer.Did, _agent.Did, Vocabulary, CredentialId, Recipient,
            new Uri("http://api.example/projects/project-42"), Action,
            _issuer.Seed, Now.AddSeconds(-5), Now.AddMinutes(5)));

        // A real issuer can sign a long-lived generic VC2 with identical
        // fields. The additional agent-specific lifetime gate MUST still fail.
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _agent.Did, action = Action, resource = Resource.AbsoluteUri
        }));
        string longLived = Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuer.Did, _agent.Did, Vcdm20AgentScopeAssertion.CredentialType,
            Vocabulary, subject.RootElement, _issuer.Seed,
            Now.AddMinutes(-1), Now.AddHours(1), CredentialId, Recipient);
        Assert.False(Check(longLived, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    private string Issue() => Vcdm20AgentScopeAssertion.Create(
        _issuer.Did, _agent.Did, Vocabulary, CredentialId, Recipient,
        Resource, Action, _issuer.Seed, Now.AddSeconds(-5), Now.AddMinutes(5));

    private bool Check(
        string jwt, out JsonElement scope,
        string? trustedIssuer = null, string? agent = null,
        Uri? recipient = null, Uri? resource = null, string? action = null,
        Uri? credentialId = null, Uri? context = null, DateTimeOffset? now = null)
        => Vcdm20AgentScopeAssertion.TryVerify(
            jwt, trustedIssuer ?? _issuer.Did, agent ?? _agent.Did,
            context ?? Vocabulary, credentialId ?? CredentialId,
            recipient ?? Recipient, resource ?? Resource,
            action ?? Action, now ?? Now, out scope);

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
