using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Full-disclosure VC1.1 issuer/holder cryptographic separation with explicit
/// verifier-owned trust pins and a one-use verifier challenge. No consent UI.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebIssuerPresentationTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string Method = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");

    [Fact]
    public void IndependentlySignedDidWebCredentialAndDidKeyHolderVpConsumeOnce()
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        var clock = TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + verifier.Did;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(tenant, audience, IssuerDid);
        string original = Issue(issuer, holder.Did, clock);
        string vp = Create(challenge, original, issuer.PublicKey, holder, clock);

        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(vp));
        Assert.Equal(holder.Did, payload.RootElement.GetProperty("iss").GetString());
        Assert.Equal(challenge.Nonce, payload.RootElement.GetProperty("nonce").GetString());
        Assert.Equal(original, payload.RootElement.GetProperty("vp")
            .GetProperty("verifiableCredential")[0].GetString());

        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            Check(vp, tenant, audience, challenge.Nonce, issuer.PublicKey, store, clock,
                out JsonElement claims));
        Assert.Equal("member", claims.GetProperty("role").GetString());

        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            Check(vp, tenant, audience, challenge.Nonce, issuer.PublicKey, store, clock,
                out JsonElement replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void WalletRefusesForeignIssuerPinNameIdAndWrongHolderSigningKey()
    {
        var issuer = Identity();
        var holder = Identity();
        var attacker = Identity();
        var clock = TimeProvider.System;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(Guid.NewGuid(), "decentralized_identifier:" + attacker.Did, IssuerDid);
        string original = Issue(issuer, holder.Did, clock);

        Assert.Throws<ArgumentException>(() =>
            Create(challenge, original, attacker.PublicKey, holder, clock));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerPresentation.Create(challenge, original,
                IssuerDid, Method, issuer.PublicKey, "Foreign Office", CredentialId,
                CredentialType, Context, holder.Did, holder.Seed, clock));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerPresentation.Create(challenge, original,
                IssuerDid, Method, issuer.PublicKey, IssuerName,
                new Uri("https://issuer.example/credentials/other"), CredentialType,
                Context, holder.Did, holder.Seed, clock));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebIssuerPresentation.Create(challenge, original,
                IssuerDid, Method, issuer.PublicKey, IssuerName, CredentialId,
                CredentialType, Context, holder.Did, attacker.Seed, clock));
    }

    [Fact]
    public void WrongVerifierPolicyDoesNotConsumeAndForgedCredentialCannotLaunderViaHolder()
    {
        var issuer = Identity();
        var holder = Identity();
        var attacker = Identity();
        var clock = TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + attacker.Did;
        var store = new InMemoryPresentationChallengeStore(clock);
        var challenge = store.Issue(tenant, audience, IssuerDid);
        string original = Issue(issuer, holder.Did, clock);
        string vp = Create(challenge, original, issuer.PublicKey, holder, clock);

        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            Check(vp, tenant, audience, challenge.Nonce, attacker.PublicKey,
                store, clock, out JsonElement wrongIssuerKey));
        Assert.Equal(JsonValueKind.Undefined, wrongIssuerKey.ValueKind);
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            Check(vp, Guid.NewGuid(), audience, challenge.Nonce, issuer.PublicKey,
                store, clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            Check(vp, tenant, audience, "not-the-nonce", issuer.PublicKey,
                store, clock, out _));

        string[] parts = original.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(original)
            .Replace("member", "administrator", StringComparison.Ordinal));
        string forgedCredential = string.Join('.', parts);
        string reSignedByHolder = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(vp),
            Ed25519JwtSigner.ExtractPayload(vp).Replace(original, forgedCredential,
                StringComparison.Ordinal), holder.Seed);
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            Check(reSignedByHolder, tenant, audience, challenge.Nonce, issuer.PublicKey,
                store, clock, out JsonElement forgedClaims));
        Assert.Equal(JsonValueKind.Undefined, forgedClaims.ValueKind);

        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            Check(vp, tenant, audience, challenge.Nonce, issuer.PublicKey, store, clock,
                out JsonElement verified));
        Assert.Equal("member", verified.GetProperty("role").GetString());
    }

    private static string Create(
        PresentationChallenge challenge, string jwt, byte[] publicKey,
        (byte[] Seed, byte[] PublicKey, string Did) holder, TimeProvider clock) =>
        JwtVcJsonPinnedDidWebIssuerPresentation.Create(challenge, jwt, IssuerDid,
            Method, publicKey, IssuerName, CredentialId, CredentialType, Context,
            holder.Did, holder.Seed, clock);

    private static JwtVcJsonPresentationCheckResult Check(
        string vp, Guid tenant, string audience, string nonce, byte[] publicKey,
        IPresentationChallengeStore store, TimeProvider clock, out JsonElement claims) =>
        JwtVcJsonPinnedDidWebIssuerPresentation.Check(vp, tenant, audience, nonce,
            IssuerDid, Method, publicKey, IssuerName, CredentialId, CredentialType,
            Context, store, clock, out claims);

    private static string Issue(
        (byte[] Seed, byte[] PublicKey, string Did) issuer, string holderDid,
        TimeProvider clock)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        DateTimeOffset now = clock.GetUtcNow();
        return JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, Method, issuer.PublicKey, holderDid, CredentialType,
            Context, document.RootElement, issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(4), IssuerName, CredentialId);
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
}
