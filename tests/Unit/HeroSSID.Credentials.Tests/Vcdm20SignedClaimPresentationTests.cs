using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20SignedClaimPresentationTests
{
    private const string Audience = "https://verifier.example/member";
    private static readonly Uri Context = new("https://issuer.example/member-context/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/42");
    private readonly TimeProvider _clock = TimeProvider.System;

    [Theory]
    [InlineData("active", true)]
    [InlineData("inactive", false)]
    [InlineData("Active", false)]
    public void SignedMembershipAndHolderMustBothPass(string membership, bool expected)
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        var store = new InMemoryPresentationChallengeStore(_clock);
        Guid tenant = Guid.NewGuid();
        var challenge = store.Issue(tenant, Audience, issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(
            challenge, verifier.Did, verifier.Seed, _clock);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership }));
        var now = _clock.GetUtcNow();
        string credential = Vcdm20JoseCredential.CreateWithId(
            issuer.Did, holder.Did, "MembershipCredential", Context,
            subject.RootElement, issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(5), CredentialId);
        string presentation = Vcdm20JosePresentation.Create(
            request, verifier.Did, Audience, credential, "MembershipCredential",
            Context, holder.Did, holder.Seed, _clock);
        var policy = new Dictionary<string, string> { ["membership"] = "active" };
        var result = Vcdm20SignedClaimPresentation.Check(
            presentation, tenant, Audience, challenge.Nonce, "MembershipCredential",
            Context, store, [issuer.Did], holder.Did, CredentialId, policy,
            _clock, out string signer, out JsonElement claims);
        Assert.Equal(expected, result == Vcdm20PresentationCheckResult.SignedButStatusUnchecked);
        Assert.Equal(expected ? issuer.Did : string.Empty, signer);
        Assert.Equal(expected ? JsonValueKind.Object : JsonValueKind.Undefined, claims.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20SignedClaimPresentation.Check(
                presentation, tenant, Audience, challenge.Nonce, "MembershipCredential",
                Context, store, [issuer.Did], holder.Did, CredentialId, policy,
                _clock, out _, out _));
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
