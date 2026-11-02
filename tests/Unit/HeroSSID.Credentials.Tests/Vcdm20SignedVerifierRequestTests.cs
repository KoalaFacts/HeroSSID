using System.Security.Cryptography;
using System.Text;
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

    [Fact]
    public void ASecondAuthenticRequestForSameNonceCannotReplaceTheOriginalDigestPin()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        var originalTime = _clock.GetUtcNow();
        string originallyIssuedRequest = OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = Type, SubjectContextUri = Context },
            _verifier.Did, _verifier.Seed, new FixedClock(originalTime.AddSeconds(-2)));
        string alternativeAlsoSignedRequest = OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = Type, SubjectContextUri = Context },
            _verifier.Did, _verifier.Seed, new FixedClock(originalTime.AddSeconds(-1)));
        Assert.NotEqual(Pin(originallyIssuedRequest), Pin(alternativeAlsoSignedRequest));
        string presentation = SignPresentation(originallyIssuedRequest,
            IssueCredential(Type, Context), Type, Context);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, Array.Empty<string>(), _issuer.Seed, _clock.GetUtcNow(), _clock);

        // Same real verifier signature, nonce, type, context, issuer and expiry.
        // Only the verifier-owned original request SHA-256 pin distinguishes them.
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            CheckWithPin(presentation, alternativeAlsoSignedRequest, Pin(originallyIssuedRequest),
                tenant, challenge, Type, Context, store, out var wrongRequest));
        Assert.Equal(JsonValueKind.Undefined, wrongRequest.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            CheckStatusWithPin(presentation, alternativeAlsoSignedRequest,
                Pin(originallyIssuedRequest), snapshot, tenant, challenge,
                Type, Context, store, out var wrongStatus));
        Assert.Equal(JsonValueKind.Undefined, wrongStatus.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            CheckWithPin(presentation, originallyIssuedRequest, Pin(originallyIssuedRequest).ToUpperInvariant(),
                tenant, challenge, Type, Context, store, out var noncanonicalPin));
        Assert.Equal(JsonValueKind.Undefined, noncanonicalPin.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            CheckStatusWithPin(presentation, originallyIssuedRequest,
                Pin(originallyIssuedRequest), snapshot, tenant, challenge,
                Type, Context, store, out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    [Fact]
    public void HolderSignedOriginalRequestHashCannotBeReplacedByAnotherAuthenticRequest()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        var now = _clock.GetUtcNow();
        var bound = challenge with { CredentialType = Type, SubjectContextUri = Context };
        string original = OfflineSignedPresentationRequest.Create(
            bound, _verifier.Did, _verifier.Seed, new FixedClock(now.AddSeconds(-2)));
        string alternate = OfflineSignedPresentationRequest.Create(
            bound, _verifier.Did, _verifier.Seed, new FixedClock(now.AddSeconds(-1)));
        Assert.NotEqual(Pin(original), Pin(alternate));
        string credential = IssueCredential(Type, Context);
        string presentationForAlternate = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            alternate, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                presentationForAlternate, original, Pin(original), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        string presentationForOriginal = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            original, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                presentationForOriginal, original, Pin(original), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                presentationForOriginal, original, Pin(original), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void StrictVerifierRejectsLegacyHolderProofWithoutRequestHashBeforeNonceUse()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string credential = IssueCredential(Type, Context);
        string legacyProof = SignPresentation(request, credential, Type, Context);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                legacyProof, request, Pin(request), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        string strongProof = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            request, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                strongProof, request, Pin(request), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    [Fact]
    public void HolderBoundStatusCheckNeedsRealIssuerStatusAndExactRequestProof()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string credential = IssueCredential(Type, Context);
        string presentation = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            request, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);
        string unlisted = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, Array.Empty<string>(), _issuer.Seed, _clock.GetUtcNow(), _clock);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                presentation, request, Pin(request).ToUpperInvariant(), _verifier.Did,
                unlisted, tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var badPin));
        Assert.Equal(JsonValueKind.Undefined, badPin.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                presentation, request, Pin(request), _verifier.Did, unlisted,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    [Fact]
    public void HolderBoundRevokedCredentialFailsWithoutDisclosureAndSpendsTheNonce()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string credential = IssueCredential(Type, Context);
        string holderProof = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            request, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);
        string revoked = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, _clock.GetUtcNow(), _clock);

        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                holderProof, request, Pin(request), _verifier.Did, revoked,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest(
                holderProof, request, Pin(request), _verifier.Did, revoked,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var replay));
        Assert.Equal(JsonValueKind.Undefined, replay.ValueKind);
    }

    [Fact]
    public void ForgedHolderRequestDigestAndWrongTenantNeverReleaseClaims()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = SignBound(challenge);
        string holderProof = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
            request, _verifier.Did, Audience, IssueCredential(Type, Context),
            Type, Context, _holder.Did, _holder.Seed, _clock);
        string signedPayload = HeroSSID.Credentials.Utilities.Ed25519JwtSigner
            .ExtractPayload(holderProof);
        string corruptedDigest = new string('a', 64);
        if (string.Equals(corruptedDigest, Pin(request), StringComparison.Ordinal))
        {
            corruptedDigest = new string('b', 64);
        }

        string forgedPayload = signedPayload.Replace(
            Pin(request), corruptedDigest, StringComparison.Ordinal);
        Assert.NotEqual(signedPayload, forgedPayload);
        string[] fragments = holderProof.Split('.');
        fragments[1] = HeroSSID.Credentials.Utilities.Base64UrlEncoder.Encode(forgedPayload);
        string tamperedProof = string.Join('.', fragments);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                tamperedProof, request, Pin(request), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var forged));
        Assert.Equal(JsonValueKind.Undefined, forged.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                holderProof, request, Pin(request), _verifier.Did,
                Guid.NewGuid(), Audience, challenge.Nonce, Type, Context, store, _clock,
                out var foreignTenant));
        Assert.Equal(JsonValueKind.Undefined, foreignTenant.ValueKind);

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                holderProof, request, Pin(request), _verifier.Did,
                tenant, Audience, challenge.Nonce, Type, Context, store, _clock,
                out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }

    private Vcdm20PresentationCheckResult Check(
        string presentation, string request, Guid tenant, PresentationChallenge challenge,
        string type, Uri context, IPresentationChallengeStore store, out JsonElement claims) =>
        CheckWithPin(presentation, request, Pin(request),
            tenant, challenge, type, context, store, out claims);

    private Vcdm20PresentationCheckResult CheckWithPin(
        string presentation, string request, string trustedRequestDigest,
        Guid tenant, PresentationChallenge challenge, string type, Uri context,
        IPresentationChallengeStore store, out JsonElement claims) =>
        Vcdm20JosePresentation.CheckWithPinnedSignedVerifierRequest(
            presentation, request, trustedRequestDigest, _verifier.Did,
            tenant, Audience, challenge.Nonce, type, context, store, _clock, out claims);

    private Vcdm20RevocationCheckResult CheckStatus(
        string presentation, string request, string snapshot, Guid tenant,
        PresentationChallenge challenge, string type, Uri context,
        IPresentationChallengeStore store, out JsonElement claims) =>
        CheckStatusWithPin(presentation, request, Pin(request), snapshot,
            tenant, challenge, type, context, store, out claims);

    private Vcdm20RevocationCheckResult CheckStatusWithPin(
        string presentation, string request, string trustedRequestDigest, string snapshot,
        Guid tenant, PresentationChallenge challenge, string type, Uri context,
        IPresentationChallengeStore store, out JsonElement claims) =>
        Vcdm20RevocationSnapshot.CheckPresentationWithPinnedSignedVerifierRequest(
            presentation, request, trustedRequestDigest, _verifier.Did, snapshot,
            tenant, Audience, challenge.Nonce, type, context, store, _clock, out claims);

    private static string Pin(string request) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request)));

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

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
