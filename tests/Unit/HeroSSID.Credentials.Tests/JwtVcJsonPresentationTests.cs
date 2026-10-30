using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonPresentationTests
{
    private const string Type = "MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;
    private string Audience => "decentralized_identifier:" + _verifier.Did;

    [Fact]
    public void ActualIssuerAndHolderSignaturesWithNestedJwtVpAndAtomicReplay()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string credential = IssueCredential();
        string presentation = JwtVcJsonPresentation.Create(request, _verifier.Did, Audience,
            credential, Type, Vocabulary, _holder.Did, _holder.Seed, _clock);

        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(presentation));
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        Assert.Equal("vp+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(_holder.Did + "#" + _holder.Did["did:key:".Length..],
            header.RootElement.GetProperty("kid").GetString());
        var payload = document.RootElement;
        Assert.Equal(_holder.Did, payload.GetProperty("iss").GetString());
        Assert.Equal(Audience, payload.GetProperty("aud").GetString());
        Assert.Equal(challenge.Nonce, payload.GetProperty("nonce").GetString());
        Assert.Equal(payload.GetProperty("iat").GetDecimal(), payload.GetProperty("nbf").GetDecimal());
        var vp = payload.GetProperty("vp");
        Assert.False(payload.TryGetProperty("verifiableCredential", out _));
        Assert.Equal("https://www.w3.org/2018/credentials/v1", vp.GetProperty("@context")[0].GetString());
        Assert.Equal("VerifiablePresentation", vp.GetProperty("type")[0].GetString());
        Assert.Equal(credential, vp.GetProperty("verifiableCredential")[0].GetString());

        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out var verified));
        Assert.Equal(_holder.Did, verified.GetProperty("id").GetString());
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void HolderRejectsForgedVerifierWrongAudienceIssuerAndHolderSeed()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string credential = IssueCredential();
        Assert.Throws<ArgumentException>(() => JwtVcJsonPresentation.Create(
            request, _other.Did, Audience, credential, Type, Vocabulary,
            _holder.Did, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() => JwtVcJsonPresentation.Create(
            request, _verifier.Did, "decentralized_identifier:" + _other.Did,
            credential, Type, Vocabulary, _holder.Did, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() => JwtVcJsonPresentation.Create(
            request, _verifier.Did, Audience, credential, Type, Vocabulary,
            _holder.Did, _other.Seed, _clock));
        string alternateIssuer = IssueCredential(_other);
        Assert.Throws<ArgumentException>(() => JwtVcJsonPresentation.Create(
            request, _verifier.Did, Audience, alternateIssuer, Type, Vocabulary,
            _holder.Did, _holder.Seed, _clock));
    }

    [Fact]
    public void ForgedIssuerPayloadCannotBeLaunderedByLegitimateHolderSignature()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string credential = IssueCredential();
        string presentation = JwtVcJsonPresentation.Create(request, _verifier.Did, Audience,
            credential, Type, Vocabulary, _holder.Did, _holder.Seed, _clock);

        var parts = credential.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(credential)
            .Replace("active", "admin", StringComparison.Ordinal));
        string tamperedCredential = string.Join('.', parts);
        string resignedVp = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(presentation),
            Ed25519JwtSigner.ExtractPayload(presentation).Replace(
                credential, tamperedCredential, StringComparison.Ordinal),
            _holder.Seed);

        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(resignedVp, tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out _));
    }

    [Fact]
    public void WrongTenantNonceTypeContextAndTamperedHolderSignatureAreRejectedWithoutClaims()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string presentation = JwtVcJsonPresentation.Create(request, _verifier.Did, Audience,
            IssueCredential(), Type, Vocabulary, _holder.Did, _holder.Seed, _clock);
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(presentation, Guid.NewGuid(), Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, "not-the-nonce",
                Type, Vocabulary, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                "AdminCredential", Vocabulary, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, new Uri("https://untrusted.example/v1"), store, _clock, out _));
        var parts = presentation.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(presentation)
            .Replace(_holder.Did, _other.Did, StringComparison.Ordinal));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(string.Join('.', parts), tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            JwtVcJsonPresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Vocabulary, store, _clock, out _));
    }

    [Fact]
    public void DirectVc2CredentialCannotEnterNestedJwtVcJsonPresentation()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(Guid.NewGuid(), Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        DateTimeOffset now = _clock.GetUtcNow();
        string direct = Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, Type, Vocabulary,
            subject.RootElement, _issuer.Seed, now.AddSeconds(-5), now.AddMinutes(5));
        Assert.Throws<ArgumentException>(() => JwtVcJsonPresentation.Create(
            request, _verifier.Did, Audience, direct, Type, Vocabulary,
            _holder.Did, _holder.Seed, _clock));
    }

    private string IssueCredential() => IssueCredential(_issuer);

    private string IssueCredential((byte[] Seed, string Did) signer)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        var now = _clock.GetUtcNow();
        return JwtVcJsonCredential.Create(signer.Did, _holder.Did, Type, Vocabulary,
            subject.RootElement, signer.Seed, now.AddSeconds(-5), now.AddMinutes(5));
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var raw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        raw.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
