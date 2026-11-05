using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20SignedIdWalletDisclosureTests
{
    private const string Audience = "https://verifier.example/member-check";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/member-v1");
    private static readonly Uri CredentialId = new("https://issuer.example/member-credentials/42");

    [Fact]
    public void ConsentedStatusPreviewProducesGenuineOneUseMembershipProof()
    {
        var scenario = new Scenario();
        Assert.True(scenario.Preview(out var preview));
        Assert.NotNull(preview);
        Assert.Equal("active", preview.VerifiedSubject.GetProperty("membership").GetString());
        Assert.Equal(CredentialId, preview.CredentialId);

        // Application must present EVERY field and obtain real informed consent here.
        string vp = Vcdm20SignedIdWalletDisclosure.CreateAfterPreview(
            preview, scenario.Request, scenario.Credential, scenario.Status,
            scenario.Holder.Seed, scenario.Clock);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20SignedClaimPresentation.CheckWithIssuerStatus(
                vp, scenario.Status, scenario.Tenant, Audience, scenario.Challenge.Nonce,
                CredentialType, Context, scenario.Store, [scenario.Issuer.Did],
                scenario.Holder.Did, CredentialId, scenario.RequiredClaims,
                scenario.Cutoff, scenario.Clock, out var signer, out var subject));
        Assert.Equal(scenario.Issuer.Did, signer);
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20SignedClaimPresentation.CheckWithIssuerStatus(
                vp, scenario.Status, scenario.Tenant, Audience, scenario.Challenge.Nonce,
                CredentialType, Context, scenario.Store, [scenario.Issuer.Did],
                scenario.Holder.Did, CredentialId, scenario.RequiredClaims,
                scenario.Cutoff, scenario.Clock, out _, out _));
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("inactive")]
    [InlineData("foreign-status")]
    [InlineData("stale-status")]
    [InlineData("wrong-id")]
    public void NegativeStatusOrPolicyNeverExposesClaims(string variant)
    {
        var scenario = new Scenario(variant);
        Assert.False(scenario.Preview(out var preview));
        Assert.Null(preview);
    }

    [Fact]
    public void PresentationCannotSignSubstitutedCredentialOrStatusAfterConsent()
    {
        var scenario = new Scenario();
        Assert.True(scenario.Preview(out var preview));
        Assert.NotNull(preview);

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = scenario.Holder.Did, membership = "active", tier = "premium" }));
        string otherGenuineCredential = Vcdm20JoseCredential.CreateWithId(
            scenario.Issuer.Did, scenario.Holder.Did, CredentialType, Context,
            subject.RootElement, scenario.Issuer.Seed, scenario.Clock.GetUtcNow().AddMinutes(-1),
            scenario.Clock.GetUtcNow().AddMinutes(5), CredentialId);
        string otherGenuineStatus = Vcdm20RevocationSnapshot.Create(
            scenario.Issuer.Did, [], scenario.Issuer.Seed,
            scenario.Clock.GetUtcNow().AddSeconds(-1), scenario.Clock);

        Assert.Throws<ArgumentException>(() =>
            Vcdm20SignedIdWalletDisclosure.CreateAfterPreview(
                preview, scenario.Request, otherGenuineCredential, scenario.Status,
                scenario.Holder.Seed, scenario.Clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20SignedIdWalletDisclosure.CreateAfterPreview(
                preview, scenario.Request, scenario.Credential, otherGenuineStatus,
                scenario.Holder.Seed, scenario.Clock));

        var attacker = Identity();
        Assert.Throws<ArgumentException>(() =>
            Vcdm20SignedIdWalletDisclosure.CreateAfterPreview(
                preview, scenario.Request, scenario.Credential, scenario.Status,
                attacker.Seed, scenario.Clock));
    }

    private sealed class Scenario
    {
        public (byte[] Seed, string Did) Issuer { get; } = Identity();
        public (byte[] Seed, string Did) Holder { get; } = Identity();
        public (byte[] Seed, string Did) Verifier { get; } = Identity();
        public TimeProvider Clock { get; } = TimeProvider.System;
        public Guid Tenant { get; } = Guid.NewGuid();
        public InMemoryPresentationChallengeStore Store { get; }
        public PresentationChallenge Challenge { get; }
        public string Request { get; }
        public string Credential { get; }
        public string Status { get; }
        public DateTimeOffset Cutoff { get; }
        public IReadOnlyDictionary<string, string> RequiredClaims { get; } =
            new Dictionary<string, string> { ["membership"] = "active" };

        public Scenario(string variant = "valid")
        {
            Store = new InMemoryPresentationChallengeStore(Clock);
            Challenge = Store.Issue(Tenant, Audience, Issuer.Did);
            Request = OfflineSignedPresentationRequest.Create(
                Challenge with { CredentialType = CredentialType, SubjectContextUri = Context },
                Verifier.Did, Verifier.Seed, Clock);
            DateTimeOffset now = Clock.GetUtcNow();
            Cutoff = now.AddSeconds(-5);
            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
                new { id = Holder.Did, membership = variant == "inactive" ? "inactive" : "active" }));
            Credential = Vcdm20JoseCredential.CreateWithId(
                Issuer.Did, Holder.Did, CredentialType, Context,
                subject.RootElement, Issuer.Seed, now.AddMinutes(-1),
                now.AddMinutes(5),
                variant == "wrong-id" ? new Uri("https://issuer.example/member-credentials/other") : CredentialId);
            var statusSigner = variant == "foreign-status" ? Identity() : Issuer;
            DateTimeOffset observed = variant == "stale-status" ? now.AddSeconds(-30) : now.AddSeconds(-2);
            Status = Vcdm20RevocationSnapshot.Create(
                statusSigner.Did, variant == "revoked" ? [Credential] : [],
                statusSigner.Seed, observed, Clock);
        }

        public bool Preview(out Vcdm20SignedIdWalletPreview? preview) =>
            Vcdm20SignedIdWalletDisclosure.TryPrepare(
                Request, Verifier.Did, Audience, CredentialType, Context,
                Issuer.Did, Credential, Holder.Did, CredentialId, RequiredClaims,
                Status, Cutoff, Clock, out preview);
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
