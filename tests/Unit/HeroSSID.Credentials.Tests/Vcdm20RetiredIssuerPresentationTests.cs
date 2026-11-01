using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20RetiredIssuerPresentationTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Audience = "https://verifier.example/verify";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/context/membership/v2");
    private readonly (byte[] Seed, string Did) _retired = NewIdentity();
    private readonly (byte[] Seed, string Did) _active = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _verifier = NewIdentity();
    private readonly FixedClock _clock = new(Now);

    [Fact]
    public void RetiredIssuerExactPinRejectsAuthenticPreIncidentStatusWithoutDisclosingClaims()
    {
        string original = Issue(_retired);
        var pins = new[] { Pin(_retired.Did, original) };
        string stale = Vcdm20RevocationSnapshot.Create(
            _retired.Did, [], _retired.Seed, Now.AddSeconds(-25), _clock);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            Vcdm20RetiredIssuerVerifier.CheckWithStatus(
                original, stale, [_active.Did], pins, _holder.Did, Type,
                Context, Now, out _, out _));

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff(
                original, stale, [_active.Did], pins, _holder.Did, Type,
                Context, Now, Now.AddSeconds(-10),
                out string rejectedSigner, out var rejectedClaims));
        Assert.Equal(string.Empty, rejectedSigner);
        Assert.Equal(JsonValueKind.Undefined, rejectedClaims.ValueKind);

        string fresh = Snapshot(_retired, []);
        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff(
                original, fresh, [_active.Did], pins, _holder.Did, Type,
                Context, Now, Now.AddSeconds(-10),
                out string actualSigner, out var acceptedClaims));
        Assert.Equal(_retired.Did, actualSigner);
        Assert.Equal("member", acceptedClaims.GetProperty("membership").GetString());
    }

    [Fact]
    public void RetiredHolderPresentationRejectsStaleStatusAndConsumesOneUseProof()
    {
        string original = Issue(_retired);
        var pins = new[] { Pin(_retired.Did, original) };
        string stale = Vcdm20RevocationSnapshot.Create(
            _retired.Did, [], _retired.Seed, Now.AddSeconds(-25), _clock);
        string fresh = Snapshot(_retired, []);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, original, tenant, store);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff(
                presentation, stale, tenant, Audience, nonce, Type, Context,
                store, [_active.Did], pins, Now.AddSeconds(-10), _clock,
                out string rejectedSigner, out var rejectedClaims));
        Assert.Equal(string.Empty, rejectedSigner);
        Assert.Equal(JsonValueKind.Undefined, rejectedClaims.ValueKind);
        AssertInvalid(presentation, nonce, tenant, store, [_active.Did], pins);

        (presentation, nonce) = Present(_retired, original, tenant, store);
        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff(
                presentation, fresh, tenant, Audience, nonce, Type, Context,
                store, [_active.Did], pins, Now.AddSeconds(-10), _clock,
                out string signer, out var claims));
        Assert.Equal(_retired.Did, signer);
        Assert.Equal(_holder.Did, claims.GetProperty("id").GetString());
    }

    [Fact]
    public void InvalidFutureCutoffDoesNotSpendHolderChallengeAndRevocationStillBlocks()
    {
        string original = Issue(_retired);
        var pins = new[] { Pin(_retired.Did, original) };
        string clean = Snapshot(_retired, []);
        string revoked = Snapshot(_retired, [original]);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, original, tenant, store);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff(
                presentation, clean, tenant, Audience, nonce, Type, Context,
                store, [_active.Did], pins, Now.AddSeconds(1), _clock,
                out string futureSigner, out var futureClaims));
        Assert.Equal(string.Empty, futureSigner);
        Assert.Equal(JsonValueKind.Undefined, futureClaims.ValueKind);

        // Invalid verifier policy must not burn the holder's real consented challenge.
        Assert.Equal(Vcdm20VerifierPolicyResult.IssuerReportedRevoked,
            Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff(
                presentation, revoked, tenant, Audience, nonce, Type, Context,
                store, [_active.Did], pins, Now.AddSeconds(-10), _clock,
                out string revokedSigner, out var revokedClaims));
        Assert.Equal(string.Empty, revokedSigner);
        Assert.Equal(JsonValueKind.Undefined, revokedClaims.ValueKind);
        AssertInvalid(presentation, nonce, tenant, store, [_active.Did], pins);
    }

    [Fact]
    public void FractionalSecondCutoffDoesNotAcceptSignedWholeSecondStatus()
    {
        string original = Issue(_retired);
        var pins = new[] { Pin(_retired.Did, original) };
        DateTimeOffset observed = Now.AddSeconds(-1);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _retired.Did, [], _retired.Seed, observed, _clock);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff(
                original, snapshot, [], pins, _holder.Did, Type, Context,
                Now, observed, out _, out _));
        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff(
                original, snapshot, [], pins, _holder.Did, Type, Context,
                Now, observed.AddTicks(1), out string signer, out var claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    [Fact]
    public void ExactPinnedRetiredCredentialRequiresRealHolderProofAndOneUseNonce()
    {
        string historical = Issue(_retired);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, historical, tenant, store);
        var pins = new[] { Pin(_retired.Did, historical) };

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(presentation, nonce, tenant, store, [_active.Did], pins,
                out string signer, out var claims));
        Assert.Equal(_retired.Did, signer);
        Assert.Equal("member", claims.GetProperty("membership").GetString());

        AssertInvalid(presentation, nonce, tenant, store, [_active.Did], pins);
    }

    [Fact]
    public void IndependentlyTrustedActiveIssuerCanProveHolderWithoutHistoricalPin()
    {
        string current = Issue(_active);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_active, current, tenant, store);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(presentation, nonce, tenant, store, [_active.Did], [],
                out string signer, out var claims));
        Assert.Equal(_active.Did, signer);
        Assert.Equal(_holder.Did, claims.GetProperty("id").GetString());
    }

    [Fact]
    public void RetiredUnpinnedJwtIsDeniedWithoutClaimsAndItsHolderProofIsSpent()
    {
        string historical = Issue(_retired);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, historical, tenant, store);
        AssertInvalid(presentation, nonce, tenant, store, [_active.Did], []);
        AssertInvalid(presentation, nonce, tenant, store, [_active.Did],
            [Pin(_retired.Did, historical)]);
    }

    [Fact]
    public void TamperedHolderSignatureCannotConsumeLegitimateRequest()
    {
        string historical = Issue(_retired);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, historical, tenant, store);
        var pins = new[] { Pin(_retired.Did, historical) };
        var segments = presentation.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(presentation)
                .Replace(_holder.Did, _active.Did, StringComparison.Ordinal));
        string forged = string.Join('.', segments);

        AssertInvalid(forged, nonce, tenant, store, [], pins);
        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(presentation, nonce, tenant, store, [], pins, out _, out _));
    }

    [Fact]
    public void WrongTenantOrTrustPolicyCannotLeakSubjectOrBypassHolderChallenge()
    {
        string historical = Issue(_retired);
        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, historical, tenant, store);
        var pins = new[] { Pin(_retired.Did, historical) };

        AssertInvalid(presentation, nonce, Guid.NewGuid(), store, [], pins);
        AssertInvalid(presentation, nonce, tenant, store, [_retired.Did], pins);
        AssertInvalid(presentation, nonce, tenant, store, [], pins);
    }

    [Fact]
    public void AuthenticatedIssuerStatusMustMatchOriginalIssuerAndIsNeverLiveClearance()
    {
        string historical = Issue(_retired);
        var pins = new[] { Pin(_retired.Did, historical) };
        string clean = Snapshot(_retired, []);
        string revoked = Snapshot(_retired, [historical]);
        string wrongSigner = Snapshot(_active, []);

        var store = NewStore();
        Guid tenant = Guid.NewGuid();
        var (presentation, nonce) = Present(_retired, historical, tenant, store);
        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            CheckWithStatus(presentation, clean, nonce, tenant, store, [], pins,
                out string signer, out var claims));
        Assert.Equal(_retired.Did, signer);
        Assert.Equal("member", claims.GetProperty("membership").GetString());

        (presentation, nonce) = Present(_retired, historical, tenant, store);
        Assert.Equal(Vcdm20VerifierPolicyResult.IssuerReportedRevoked,
            CheckWithStatus(presentation, revoked, nonce, tenant, store, [], pins,
                out signer, out claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);

        (presentation, nonce) = Present(_retired, historical, tenant, store);
        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            CheckWithStatus(presentation, wrongSigner, nonce, tenant, store, [], pins,
                out signer, out claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private InMemoryPresentationChallengeStore NewStore() => new(_clock);

    private (string Presentation, string Nonce) Present(
        (byte[] Seed, string Did) issuer, string credential,
        Guid tenant, InMemoryPresentationChallengeStore store)
    {
        var challenge = store.Issue(tenant, Audience, issuer.Did);
        string request = OfflineSignedPresentationRequest.Create(
            challenge, _verifier.Did, _verifier.Seed, _clock);
        string signed = Vcdm20JosePresentation.Create(
            request, _verifier.Did, Audience, credential, Type, Context,
            _holder.Did, _holder.Seed, _clock);
        return (signed, challenge.Nonce);
    }

    private Vcdm20VerifierPolicyResult Check(
        string presentation, string nonce, Guid tenant,
        IPresentationChallengeStore store, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired,
        out string signer, out JsonElement subject) =>
        Vcdm20RetiredIssuerPresentation.Check(presentation, tenant, Audience, nonce,
            Type, Context, store, active, retired, _clock, out signer, out subject);

    private Vcdm20VerifierPolicyResult CheckWithStatus(
        string presentation, string status, string nonce, Guid tenant,
        IPresentationChallengeStore store, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired,
        out string signer, out JsonElement subject) =>
        Vcdm20RetiredIssuerPresentation.CheckWithStatus(presentation, status,
            tenant, Audience, nonce, Type, Context, store, active, retired,
            _clock, out signer, out subject);

    private void AssertInvalid(
        string presentation, string nonce, Guid tenant,
        IPresentationChallengeStore store, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired)
    {
        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Check(presentation, nonce, tenant, store, active, retired,
                out string signer, out var subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private string Issue((byte[] Seed, string Did) issuer)
    {
        using var document = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = _holder.Did, membership = "member" }));
        return Vcdm20JoseCredential.Create(
            issuer.Did, _holder.Did, Type, Context, document.RootElement,
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(issuer.Did, revoked, issuer.Seed, Now, _clock);

    private static Vcdm20RetiredCredentialPin Pin(string issuerDid, string original) =>
        new(issuerDid, Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(original))));

    private sealed class FixedClock(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes));
    }
}
