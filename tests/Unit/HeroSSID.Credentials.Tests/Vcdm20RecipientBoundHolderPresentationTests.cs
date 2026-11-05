using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// End-to-end genuinely signed VC2 issuance, exact recipient/ID binding, holder proof,
/// verifier-original-request pin, atomic replay and no subject release on failure.
/// </summary>
public sealed class Vcdm20RecipientBoundHolderPresentationTests
{
    private const string Audience = "https://verifier.example/check/membership";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/one");
    private static readonly Uri OtherId = new("https://issuer.example/credentials/member/two");
    private static readonly Uri Recipient = new(Audience);
    private static readonly Uri OtherRecipient = new("https://attacker.example/check/membership");

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void OneUsePresentationAuthenticatesIssuerHolderRecipientCredentialIdAndOriginalVerifierRequest()
    {
        var (tenant, store, challenge, signedRequest) = Request();
        string credential = Issue(Recipient);
        string vp = Present(signedRequest, credential);
        string pin = Digest(signedRequest);

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Check(vp, signedRequest, pin, tenant, challenge, store, Recipient,
                CredentialId, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(vp, signedRequest, pin, tenant, challenge, store, Recipient,
                CredentialId, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void HolderRejectsAuthenticCredentialsForDifferentRecipientOrIdBeforeSigning()
    {
        var (_, _, _, signedRequest) = Request();
        string forOtherRecipient = Issue(OtherRecipient);
        Assert.Throws<ArgumentException>(() => Present(signedRequest, forOtherRecipient));
        string forOtherId = Issue(Recipient, OtherId);
        Assert.Throws<ArgumentException>(() => Present(signedRequest, forOtherId));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
                signedRequest, _verifier.Did, Audience, Issue(Recipient),
                Type, Context, CredentialId, OtherRecipient, _holder.Did,
                _holder.Seed, _clock));
    }

    [Fact]
    public void GenuineHolderSignatureCannotPromoteIssuerCredentialForDifferentRecipient()
    {
        var (tenant, store, challenge, signedRequest) = Request();
        string credential = Issue(Recipient);
        string validVp = Present(signedRequest, credential);
        string wrongRecipient = Issue(OtherRecipient);
        string payload = Ed25519JwtSigner.ExtractPayload(validVp);
        Assert.Contains(credential, payload, StringComparison.Ordinal);
        string switched = payload.Replace(credential, wrongRecipient, StringComparison.Ordinal);
        string malicious = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(validVp), switched, _holder.Seed);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(malicious, signedRequest, Digest(signedRequest), tenant,
                challenge, store, Recipient, CredentialId, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Check(validVp, signedRequest, Digest(signedRequest), tenant,
                challenge, store, Recipient, CredentialId, out _));
    }

    [Fact]
    public void WrongVerifierOwnedRequestPinAndRecipientPolicyCannotConsumeChallenge()
    {
        var (tenant, store, challenge, signedRequest) = Request();
        string vp = Present(signedRequest, Issue(Recipient));
        string actualPin = Digest(signedRequest);
        string wrongPin = new string('a', 64);
        Assert.NotEqual(actualPin, wrongPin);

        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(vp, signedRequest, wrongPin, tenant, challenge, store,
                Recipient, CredentialId, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(vp, signedRequest, actualPin, tenant, challenge, store,
                OtherRecipient, CredentialId, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Check(vp, signedRequest, actualPin, tenant, challenge, store,
                Recipient, OtherId, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Check(vp, signedRequest, actualPin, tenant, challenge, store,
                Recipient, CredentialId, out _));
    }

    private (Guid Tenant, InMemoryPresentationChallengeStore Store,
        PresentationChallenge Challenge, string SignedRequest) Request()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = Type, SubjectContextUri = Context },
            _verifier.Did, _verifier.Seed, _clock);
        return (tenant, store, challenge, signedRequest);
    }

    private string Present(string request, string credential) =>
        Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
            request, _verifier.Did, Audience, credential, Type, Context,
            CredentialId, Recipient, _holder.Did, _holder.Seed, _clock);

    private Vcdm20PresentationCheckResult Check(
        string vp, string request, string digest, Guid tenant,
        PresentationChallenge challenge, InMemoryPresentationChallengeStore store,
        Uri expectedRecipient, Uri expectedId, out JsonElement subject) =>
        Vcdm20JosePresentation.CheckForAudienceWithIdAndSignedRequest(
            vp, request, digest, _verifier.Did, tenant, Audience,
            challenge.Nonce, Type, Context, expectedId, expectedRecipient,
            store, _clock, out subject);

    private string Issue(Uri recipient, Uri? id = null)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        var now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuer.Did, _holder.Did, Type, Context, subject.RootElement,
            _issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10),
            id ?? CredentialId, recipient);
    }

    private static string Digest(string request) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request)));

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
