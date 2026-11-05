using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20SignedClaimStatusTests
{
    private const string Audience = "https://verifier.example/membership";
    private static readonly Uri Context = new("https://issuer.example/member-context/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/status-42");
    private readonly TimeProvider _clock = TimeProvider.System;

    [Theory]
    [InlineData("clean", Vcdm20RevocationCheckResult.SignedNotListed, true)]
    [InlineData("revoked", Vcdm20RevocationCheckResult.Revoked, false)]
    [InlineData("other-signer", Vcdm20RevocationCheckResult.Invalid, false)]
    [InlineData("stale-observation", Vcdm20RevocationCheckResult.Invalid, false)]
    [InlineData("inactive", Vcdm20RevocationCheckResult.Invalid, false)]
    public void PinnedMembershipRequiresActualIssuerStatusAndOneUseHolderProof(
        string scenario, Vcdm20RevocationCheckResult expected, bool releasesClaims)
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        var otherIssuer = Identity();
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(
            challenge, verifier.Did, verifier.Seed, _clock);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = scenario == "inactive" ? "inactive" : "active"
        }));
        DateTimeOffset now = _clock.GetUtcNow();
        string originalJwt = Vcdm20JoseCredential.CreateWithId(
            issuer.Did, holder.Did, "MembershipCredential", Context,
            subject.RootElement, issuer.Seed,
            now.AddMinutes(-1), now.AddMinutes(5), CredentialId);
        string presentation = Vcdm20JosePresentation.CreateWithSignedCredentialId(
            request, verifier.Did, Audience, originalJwt, "MembershipCredential",
            Context, CredentialId, holder.Did, holder.Seed, _clock);

        var signer = scenario == "other-signer" ? otherIssuer : issuer;
        DateTimeOffset observed = scenario == "stale-observation"
            ? now.AddSeconds(-30) : now.AddSeconds(-2);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            signer.Did,
            scenario == "revoked" ? [originalJwt] : [],
            signer.Seed, observed, _clock);
        var policy = new Dictionary<string, string> { ["membership"] = "active" };
        Vcdm20RevocationCheckResult result =
            Vcdm20SignedClaimPresentation.CheckWithIssuerStatus(
                presentation, snapshot, tenant, Audience, challenge.Nonce,
                "MembershipCredential", Context, store, [issuer.Did],
                holder.Did, CredentialId, policy, now.AddSeconds(-5),
                _clock, out string verifiedIssuer, out JsonElement verifiedSubject);

        Assert.Equal(expected, result);
        Assert.Equal(releasesClaims ? issuer.Did : string.Empty, verifiedIssuer);
        Assert.Equal(releasesClaims ? JsonValueKind.Object : JsonValueKind.Undefined,
            verifiedSubject.ValueKind);

        // Authenticated but refused presentations cannot be retried with a
        // more permissive policy or a different status list after consumption.
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20SignedClaimPresentation.CheckWithIssuerStatus(
                presentation, snapshot, tenant, Audience, challenge.Nonce,
                "MembershipCredential", Context, store, [issuer.Did],
                holder.Did, CredentialId, policy, now.AddSeconds(-5),
                _clock, out _, out _));
    }

    [Theory]
    [InlineData(false, Vcdm20RevocationCheckResult.SignedNotListed)]
    [InlineData(true, Vcdm20RevocationCheckResult.Revoked)]
    public void SignedIdentifierCredentialHasAuthenticSignedStatus(
        bool revoked, Vcdm20RevocationCheckResult expected)
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = _clock.GetUtcNow();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        string originalJwt = Vcdm20JoseCredential.CreateWithId(
            issuer.Did, holder.Did, "MembershipCredential", Context,
            subject.RootElement, issuer.Seed,
            now.AddMinutes(-1), now.AddMinutes(5), CredentialId);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            issuer.Did, revoked ? [originalJwt] : [],
            issuer.Seed, now.AddSeconds(-2), _clock);

        Assert.Equal(expected, Vcdm20RevocationSnapshot.Check(
            snapshot, originalJwt, issuer.Did, _clock.GetUtcNow()));
    }

    [Fact]
    public void RealIssuerSignatureCannotAuthenticateAnInvalidSeventhPolicyField()
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = _clock.GetUtcNow();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        string genuine = Vcdm20JoseCredential.CreateWithId(
            issuer.Did, holder.Did, "MembershipCredential", Context,
            subject.RootElement, issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(5), CredentialId);
        string header = Ed25519JwtSigner.ExtractHeader(genuine);
        JsonObject payload = JsonNode.Parse(Ed25519JwtSigner.ExtractPayload(genuine))!.AsObject();
        // The issuer really signs an invalid HTTP identifier. A genuine
        // Ed25519 signature does not make its non-conforming VC2 valid.
        payload["id"] = "http://issuer.example/credentials/not-https";
        string invalid = Ed25519JwtSigner.CreateSignedJwt(
            header, payload.ToJsonString(), issuer.Seed);
        Assert.False(Vcdm20JoseCredential.TryVerifyWithId(
            invalid, issuer.Did, holder.Did, "MembershipCredential",
            Context, now, out _, out _));
        Assert.Throws<CryptographicException>(() =>
            Vcdm20RevocationSnapshot.Create(
                issuer.Did, [invalid], issuer.Seed, now, _clock));
        string status = Vcdm20RevocationSnapshot.Create(
            issuer.Did, [], issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(status, invalid, issuer.Did, now));
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
