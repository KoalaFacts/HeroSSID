using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20JosePresentationTests
{
    private const string Audience = "https://verifier.example/check";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void IndependentHolderPresentsActualIssuerVc2WithEnvelopedCredentialAndOneUseProof()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string credential = Issue();
        string presentation = Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
            credential, Type, Context, _holder.Did, _holder.Seed, _clock);
        using var joseHeader = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(presentation));
        Assert.Equal("vp+jwt", joseHeader.RootElement.GetProperty("typ").GetString());
        Assert.Equal("vp", joseHeader.RootElement.GetProperty("cty").GetString());
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        var payload = document.RootElement;
        Assert.False(payload.TryGetProperty("vp", out _));
        Assert.Equal("https://www.w3.org/ns/credentials/v2", payload.GetProperty("@context")[0].GetString());
        Assert.Equal(_holder.Did, payload.GetProperty("holder").GetString());
        var enclosed = payload.GetProperty("verifiableCredential")[0];
        Assert.Equal("EnvelopedVerifiableCredential", enclosed.GetProperty("type")[0].GetString());
        Assert.Equal("data:application/vc+jwt," + credential, enclosed.GetProperty("id").GetString());

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out var replayClaims));
        Assert.Equal(JsonValueKind.Undefined, replayClaims.ValueKind);
    }

    [Fact]
    public void HolderRejectsUnpinnedVerifierAndWrongOriginalIssuerBeforeDisclosing()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string issued = Issue();
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _issuer.Did, Audience,
                issued, Type, Context, _holder.Did, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _verifier.Did, "https://attacker.example/check",
                issued, Type, Context, _holder.Did, _holder.Seed, _clock));
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
                issued, Type, Context, _holder.Did, _issuer.Seed, _clock));
    }

    [Fact]
    public void TamperingAndCrossTenantOrWrongIssuerPolicyFailClosedWithoutClaims()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string presentation = Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
            Issue(), Type, Context, _holder.Did, _holder.Seed, _clock);
        var parts = presentation.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(presentation)
            .Replace("EnvelopedVerifiableCredential", "EnvelopedVerifiablePresentations", StringComparison.Ordinal));
        string forged = string.Join('.', parts);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(forged, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(presentation, Guid.NewGuid(), Audience, challenge.Nonce,
                Type, Context, store, _clock, out _));
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                "AdminCredential", Context, store, _clock, out _));
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(presentation, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out _));
    }

    [Fact]
    public void LegacyNestedJwtCannotEnterDirectVcdm20PresentationFlow()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(challenge, _verifier.Did, _verifier.Seed, _clock);
        string oldToken = Ed25519JwtSigner.CreateSignedJwt("{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\"}",
            JsonSerializer.Serialize(new { iss = _issuer.Did, sub = _holder.Did,
                vc = new { credentialSubject = new { id = _holder.Did } } }), _issuer.Seed);
        Assert.Throws<ArgumentException>(() =>
            Vcdm20JosePresentation.Create(request, _verifier.Did, Audience,
                oldToken, Type, Context, _holder.Did, _holder.Seed, _clock));
    }


    [Fact]
    public void SignedVpContentTypeMismatchCannotConsumeChallengeAndLegacyWithoutCtyStillWorks()
    {
        var tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);
        string current = Vcdm20JosePresentation.Create(
            signedRequest, _verifier.Did, Audience, Issue(), Type, Context,
            _holder.Did, _holder.Seed, _clock);
        string header = Ed25519JwtSigner.ExtractHeader(current);
        string payload = Ed25519JwtSigner.ExtractPayload(current);
        string wrongHeader = header.Replace("\"cty\":\"vp\"", "\"cty\":\"vc\"", StringComparison.Ordinal);
        Assert.NotEqual(header, wrongHeader);
        string wrong = Ed25519JwtSigner.CreateSignedJwt(wrongHeader, payload, _holder.Seed);
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(wrong, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        // Previous cty-less direct JWT presentations stay valid, while the
        // forged but genuinely holder-signed wrong-cty proof cannot spend the nonce.
        using var parsed = JsonDocument.Parse(header);
        string olderHeader = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = "vp+jwt",
            kid = parsed.RootElement.GetProperty("kid").GetString()
        });
        string older = Ed25519JwtSigner.CreateSignedJwt(olderHeader, payload, _holder.Seed);
        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            Vcdm20JosePresentation.Check(older, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid,
            Vcdm20JosePresentation.Check(older, tenant, Audience, challenge.Nonce,
                Type, Context, store, _clock, out _));
    }

    private string Issue()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        var now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, Type, Context,
            subject.RootElement, _issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10));
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
