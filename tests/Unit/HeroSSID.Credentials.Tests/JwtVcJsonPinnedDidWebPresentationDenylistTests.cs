using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>Real Ed25519 issuer/holder proof and verifier-owned exact JWT emergency denial.</summary>
public sealed class JwtVcJsonPinnedDidWebPresentationDenylistTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string Method = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");

    [Fact]
    public void RealDidWebIssuerAndIndependentHolderProofPassWithEmptyDenylistOnce()
    {
        var fixture = CreateFixture();
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.SignedButStatusUnchecked,
            Check(fixture, [], fixture.Tenant, fixture.IssuerPublicKey, out var claims));
        Assert.Equal("member", claims.GetProperty("role").GetString());
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, [], fixture.Tenant, fixture.IssuerPublicKey, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void VerifierDeniesExactOriginalIssuerJwtAndConsumesHolderChallenge()
    {
        var fixture = CreateFixture();
        string exactDigest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(fixture.CredentialJwt)));
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.DeniedByVerifier,
            Check(fixture, [exactDigest], fixture.Tenant, fixture.IssuerPublicKey,
                out var rejected));
        Assert.Equal(JsonValueKind.Undefined, rejected.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, [], fixture.Tenant, fixture.IssuerPublicKey, out _));
    }

    [Fact]
    public void MalformedOrDuplicateVerifierDenylistFailsWithoutSpendingValidNonce()
    {
        var fixture = CreateFixture();
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(fixture.CredentialJwt)));
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, ["NOT-A-SHA256"], fixture.Tenant, fixture.IssuerPublicKey,
                out var malformed));
        Assert.Equal(JsonValueKind.Undefined, malformed.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, [digest, digest], fixture.Tenant, fixture.IssuerPublicKey,
                out _));
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.SignedButStatusUnchecked,
            Check(fixture, [], fixture.Tenant, fixture.IssuerPublicKey, out var claims));
        Assert.Equal("member", claims.GetProperty("role").GetString());
    }

    [Fact]
    public void ForeignIssuerKeyAndTenantFailWithoutLaunderingOrConsumingProof()
    {
        var fixture = CreateFixture();
        var attacker = Identity();
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, [], fixture.Tenant, attacker.PublicKey, out var wrongKey));
        Assert.Equal(JsonValueKind.Undefined, wrongKey.ValueKind);
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.Invalid,
            Check(fixture, [], Guid.NewGuid(), fixture.IssuerPublicKey, out _));
        Assert.Equal(JwtVcJsonPinnedDidWebDenylistResult.SignedButStatusUnchecked,
            Check(fixture, [], fixture.Tenant, fixture.IssuerPublicKey, out var claims));
        Assert.Equal("member", claims.GetProperty("role").GetString());
    }

    private static JwtVcJsonPinnedDidWebDenylistResult Check(
        Fixture fixture, IReadOnlyCollection<string> denied, Guid tenant,
        byte[] issuerPublicKey, out JsonElement claims) =>
        JwtVcJsonPinnedDidWebPresentationDenylist.Check(
            fixture.PresentationJwt, tenant, fixture.Audience, fixture.Nonce,
            IssuerDid, Method, issuerPublicKey, IssuerName, CredentialId,
            CredentialType, Context, denied, fixture.Store, fixture.Clock, out claims);

    private static Fixture CreateFixture()
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        var clock = TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + verifier.Did;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(tenant, audience, IssuerDid);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, role = "member" }));
        DateTimeOffset now = clock.GetUtcNow();
        string credential = JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, Method, issuer.PublicKey, holder.Did, CredentialType, Context,
            subject.RootElement, issuer.Seed, now.AddMinutes(-1), now.AddMinutes(4),
            IssuerName, CredentialId);
        string vp = JwtVcJsonPinnedDidWebIssuerPresentation.Create(
            challenge, credential, IssuerDid, Method, issuer.PublicKey,
            IssuerName, CredentialId, CredentialType, Context,
            holder.Did, holder.Seed, clock);
        return new Fixture(credential, vp, tenant, audience, challenge.Nonce,
            issuer.PublicKey, store, clock);
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

    private sealed record Fixture(
        string CredentialJwt, string PresentationJwt, Guid Tenant, string Audience,
        string Nonce, byte[] IssuerPublicKey, IPresentationChallengeStore Store,
        TimeProvider Clock);
}
