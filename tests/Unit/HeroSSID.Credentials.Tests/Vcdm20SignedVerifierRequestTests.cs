using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20SignedVerifierRequestTests
{
    private const string Audience = "https://verifier.example/presentation";
    private const string Type = "MembershipCredential";
    private const string OtherType = "AdministratorCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri OtherContext = new("https://issuer.example/contexts/admin/v1");
    private readonly TimeProvider _clock = TimeProvider.System;
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _attacker = NewIdentity();

    [Fact]
    public void RealBoundVerifierRequestAcceptsOneUseIssuerAndHolderProof()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string presentation = SignPresentation(request, IssueCredential(Type, Context), Type, Context);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Check(presentation, request, tenant, challenge, Type, Context, store, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, request, tenant, challenge, Type, Context, store, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void SignedPolicyCannotBeDowngradedToOtherAuthenticIssuerVocabulary()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string required = SignBound(challenge);
        string legacy = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string credential = IssueCredential(OtherType, OtherContext);
        string presentation = SignPresentation(legacy, credential, OtherType, OtherContext);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, required, tenant, challenge, OtherType, OtherContext, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        // Prove the signed issuer and holder would otherwise be valid, and rejection
        // did not spend the verifier's nonce or disclose a claim.
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                OtherType, OtherContext, store, _clock, out var legacyClaims));
        Assert.Equal("active", legacyClaims.GetProperty("membership").GetString());
    }

    [Fact]
    public void SignedPolicyRejectsDifferentIssuerVerifierOrRequestExpiryBeforeConsumption()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string presentation = SignPresentation(request, IssueCredential(Type, Context), Type, Context);
        var mismatchIssuer = challenge with { TrustedIssuerDid = _attacker.Did };
        string differentIssuerRequest = SignBound(mismatchIssuer);
        var mismatchExpiry = challenge with { ExpiresAt = challenge.ExpiresAt.AddSeconds(-1) };
        string differentExpiryRequest = SignBound(mismatchExpiry);
        string forgedVerifierRequest = OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = Type, SubjectContextUri = Context },
            _attacker.Did, _attacker.Seed, _clock);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, differentIssuerRequest, tenant, challenge, Type, Context, store, out var wrongIssuer));
        Assert.Equal(JsonValueKind.Undefined, wrongIssuer.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, differentExpiryRequest, tenant, challenge, Type, Context, store, out var wrongExpiry));
        Assert.Equal(JsonValueKind.Undefined, wrongExpiry.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, forgedVerifierRequest, tenant, challenge, Type, Context, store, out var forged));
        Assert.Equal(JsonValueKind.Undefined, forged.ValueKind);

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Check(presentation, request, tenant, challenge, Type, Context, store, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
    }

    [Fact]
    public void SignedPolicyRequiredEvenWhenLegacyPresentationAndIssuerStatusAreValid()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string legacy = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string presentation = SignPresentation(legacy, IssueCredential(Type, Context), Type, Context);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, Array.Empty<string>(), _issuer.Seed, _clock.GetUtcNow(), _clock);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(presentation, legacy, tenant, challenge, Type, Context, store, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckStatus(presentation, legacy, snapshot, tenant, challenge, Type, Context, store, out var statusClaims));
        Assert.Equal(JsonValueKind.Undefined, statusClaims.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentation(presentation, snapshot, tenant,
                Audience, challenge.Nonce, Type, Context, store, _clock, out var permitted));
        Assert.Equal("active", permitted.GetProperty("membership").GetString());
    }

    [Fact]
    public void SignedVerifierPolicyAndRealIssuerStatusBothRequiredBeforeClaimsAreReleased()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string credential = IssueCredential(Type, Context);
        string presentation = SignPresentation(request, credential, Type, Context);
        string status = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, Array.Empty<string>(), _issuer.Seed, _clock.GetUtcNow(), _clock);
        string wrongIssuerRequest = SignBound(challenge with { TrustedIssuerDid = _attacker.Did });

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckStatus(presentation, wrongIssuerRequest, status, tenant, challenge,
                Type, Context, store, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            CheckStatus(presentation, request, status, tenant, challenge,
                Type, Context, store, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckStatus(presentation, request, status, tenant, challenge,
                Type, Context, store, out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    private Vcdm20PresentationCheckResult Check(
        string presentation, string request, Guid tenant, PresentationChallenge challenge,
        string type, Uri context, IPresentationChallengeStore store, out JsonElement claims) =>
        Vcdm20JosePresentation.CheckWithSignedVerifierRequest(
            presentation, request, _verifier.Did, tenant, Audience, challenge.Nonce,
            type, context, store, _clock, out claims);

    private Vcdm20RevocationCheckResult CheckStatus(
        string presentation, string request, string snapshot, Guid tenant,
        PresentationChallenge challenge, string type, Uri context,
        IPresentationChallengeStore store, out JsonElement claims) =>
        Vcdm20RevocationSnapshot.CheckPresentationWithSignedVerifierRequest(
            presentation, request, _verifier.Did, snapshot, tenant, Audience,
            challenge.Nonce, type, context, store, _clock, out claims);

    private string SignBound(PresentationChallenge challenge) =>
        OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = Type, SubjectContextUri = Context },
            _verifier.Did, _verifier.Seed, _clock);

    private string SignPresentation(string request, string credential, string type, Uri context) =>
        Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
            credential, type, context, _holder.Did, _holder.Seed, _clock);

    private string IssueCredential(string type, Uri context)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        var now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, type, context,
            document.RootElement, _issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10));
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
