using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Genuine issuer, verifier and holder Ed25519 signatures, independently pinned
/// recipient/ID/request, private same-issuer status, atomic replay and no release.
/// </summary>
public sealed class Vcdm20RecipientBoundStatusPresentationTests
{
    private const string Audience = "https://verifier.example/check/membership";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/one");
    private static readonly Uri OtherCredentialId = new("https://issuer.example/credentials/member/two");
    private static readonly Uri Recipient = new(Audience);
    private static readonly Uri OtherRecipient = new("https://attacker.example/check/membership");

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void FreshAuthenticNotListedRecipientBoundProofReleasesClaimsOnce()
    {
        var (tenant, store, challenge, request) = Request();
        string credential = Issue(Recipient);
        string vp = Present(request, credential);
        string snapshot = Snapshot([]);
        DateTimeOffset cutoff = _clock.GetUtcNow().AddSeconds(-5);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Check(vp, request, snapshot, tenant, challenge, store,
                CredentialId, Recipient, cutoff, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, snapshot, tenant, challenge, store,
                CredentialId, Recipient, cutoff, out var replaySubject));
        Assert.Equal(JsonValueKind.Undefined, replaySubject.ValueKind);
    }

    [Fact]
    public void RevokedOriginalSpendsNonceWithoutReleasingClaims()
    {
        var (tenant, store, challenge, request) = Request();
        string credential = Issue(Recipient);
        string vp = Present(request, credential);
        string revoked = Snapshot([credential]);
        string clean = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Check(vp, request, revoked, tenant, challenge, store,
                CredentialId, Recipient, DateTimeOffset.UnixEpoch, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        // Cannot retry a rejected signed original with an apparently clean snapshot.
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, clean, tenant, challenge, store,
                CredentialId, Recipient, DateTimeOffset.UnixEpoch, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void ForeignIssuerStatusAndFutureObservationCutoffNeverReleaseSubject()
    {
        var (tenant, store, challenge, request) = Request();
        string credential = Issue(Recipient);
        string vp = Present(request, credential);
        var foreignIssuer = NewIdentity();
        string foreign = Vcdm20RevocationSnapshot.Create(
            foreignIssuer.Did, [], foreignIssuer.Seed,
            DateTimeOffset.FromUnixTimeSeconds(_clock.GetUtcNow().ToUnixTimeSeconds()), _clock);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, foreign, tenant, challenge, store,
                CredentialId, Recipient, DateTimeOffset.UnixEpoch, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        var (secondTenant, secondStore, secondChallenge, secondRequest) = Request();
        string secondVp = Present(secondRequest, credential);
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(secondVp, secondRequest, Snapshot([]), secondTenant,
                secondChallenge, secondStore, CredentialId, Recipient,
                _clock.GetUtcNow().AddSeconds(10), out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
    }

    [Fact]
    public void WrongRecipientOrIdPinCannotConsumeVerifiersRealChallenge()
    {
        var (tenant, store, challenge, request) = Request();
        string vp = Present(request, Issue(Recipient));
        string snapshot = Snapshot([]);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, snapshot, tenant, challenge, store,
                CredentialId, OtherRecipient, DateTimeOffset.UnixEpoch, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Check(vp, request, snapshot, tenant, challenge, store,
                OtherCredentialId, Recipient, DateTimeOffset.UnixEpoch, out denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);

        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Check(vp, request, snapshot, tenant, challenge, store,
                CredentialId, Recipient, DateTimeOffset.UnixEpoch, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    private (Guid Tenant, InMemoryPresentationChallengeStore Store,
        PresentationChallenge Challenge, string SignedRequest) Request()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.Issue(tenant, Audience, _issuer.Did);
        string signedRequest = OfflineSignedPresentationRequest.Create(
            challenge with { CredentialType = CredentialType, SubjectContextUri = Context },
            _verifier.Did, _verifier.Seed, _clock);
        return (tenant, store, challenge, signedRequest);
    }

    private string Present(string request, string credential) =>
        Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
            request, _verifier.Did, Audience, credential, CredentialType,
            Context, CredentialId, Recipient, _holder.Did, _holder.Seed, _clock);

    private string Issue(Uri recipient)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        var now = _clock.GetUtcNow();
        return Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuer.Did, _holder.Did, CredentialType, Context, doc.RootElement,
            _issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10),
            CredentialId, recipient);
    }

    private string Snapshot(IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(
            _issuer.Did, revoked, _issuer.Seed,
            DateTimeOffset.FromUnixTimeSeconds(_clock.GetUtcNow().ToUnixTimeSeconds()), _clock);

    private Vcdm20RevocationCheckResult Check(
        string vp, string request, string snapshot, Guid tenant,
        PresentationChallenge challenge, InMemoryPresentationChallengeStore store,
        Uri expectedId, Uri expectedRecipient, DateTimeOffset minimumObservedAtUtc,
        out JsonElement subject) =>
        Vcdm20RevocationSnapshot.CheckRecipientBoundPresentationWithIssuerStatus(
            vp, request, Digest(request), _verifier.Did, snapshot, tenant,
            Audience, challenge.Nonce, CredentialType, Context,
            expectedId, expectedRecipient, minimumObservedAtUtc, store, _clock,
            out subject);

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
