using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20RetiredIssuerVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v2");
    private readonly (byte[] Seed, string Did) _retired = NewIdentity();
    private readonly (byte[] Seed, string Did) _active = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void ExactHistoricalJwtAndIndependentlyEnrolledActiveIssuerAreAccepted()
    {
        string historical = Issue(_retired, "member");
        string current = Issue(_active, "member");
        var historicalPin = Pin(_retired.Did, historical);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(historical, [_active.Did], [historicalPin], Now,
                out string signer, out var subject));
        Assert.Equal(_retired.Did, signer);
        Assert.Equal("member", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(current, [_active.Did], [historicalPin], Now,
                out signer, out subject));
        Assert.Equal(_active.Did, signer);
        Assert.Equal("member", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(historical, [], [historicalPin], Now, out signer, out _));
        Assert.Equal(_retired.Did, signer);
    }

    [Fact]
    public void RetiredSigningKeyCannotBackdateOrInventNewCredentialsWithoutExactRegistration()
    {
        string historical = Issue(_retired, "member");
        string forgedLater = Issue(_retired, "administrator");
        Assert.True(Vcdm20JoseCredential.TryVerify(forgedLater,
            _retired.Did, _holder.Did, CredentialType, Context, Now, out _));

        AssertInvalid(forgedLater, [_active.Did], [Pin(_retired.Did, historical)]);
        AssertInvalid(historical, [_active.Did], []);
        AssertInvalid(Issue(_other, "member"), [_active.Did], [Pin(_retired.Did, historical)]);
        AssertInvalid(historical, [], [Pin(_other.Did, historical)]);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(forgedLater, [_active.Did], [Pin(_retired.Did, forgedLater)],
                Now, out string signer, out _));
        Assert.Equal(_retired.Did, signer);
    }

    [Fact]
    public void AmbiguousOverlappingOrInvalidEntireTrustPolicyFailsClosed()
    {
        string historical = Issue(_retired, "member");
        string current = Issue(_active, "member");
        var oldPin = Pin(_retired.Did, historical);

        AssertInvalid(current, [_active.Did], [Pin(_active.Did, current)]);
        AssertInvalid(current, [_active.Did], [oldPin, oldPin]);
        AssertInvalid(current, [_active.Did], [new(_retired.Did, "invalid-digest")]);
        AssertInvalid(current, [_active.Did], [new("did:key:invalid", oldPin.CredentialSha256)]);
        AssertInvalid(current, [_active.Did, _active.Did], [oldPin]);
        AssertInvalid(current, [], []);
        AssertInvalid(current, [_active.Did], Enumerable.Repeat(oldPin, 257).ToArray());
        AssertInvalid(current, Enumerable.Repeat(_active.Did, 17).ToArray(), []);
    }

    [Fact]
    public void RealIssuerRevocationAndWrongIssuerStatusAreRejectedBeforeDisclosure()
    {
        string historical = Issue(_retired, "member");
        var oldPin = Pin(_retired.Did, historical);
        string clean = Snapshot(_retired, []);
        string revoked = Snapshot(_retired, [historical]);
        string wrongIssuer = Snapshot(_active, []);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            CheckWithStatus(historical, clean, [_active.Did], [oldPin],
                out string signer, out var subject));
        Assert.Equal(_retired.Did, signer);
        Assert.Equal("member", subject.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20VerifierPolicyResult.IssuerReportedRevoked,
            CheckWithStatus(historical, revoked, [_active.Did], [oldPin],
                out signer, out subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            CheckWithStatus(historical, wrongIssuer, [_active.Did], [oldPin],
                out signer, out subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    [Fact]
    public void ExpiryAndWrongHolderOrVocabularyNeverDiscloseClaims()
    {
        string historical = Issue(_retired, "member");
        var pin = Pin(_retired.Did, historical);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Check(historical, [], [pin], Now.AddMinutes(20),
                out string signer, out var subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerVerifier.Check(historical, [], [pin],
                _other.Did, CredentialType, Context, Now, out signer, out subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);

        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20RetiredIssuerVerifier.Check(historical, [], [pin],
                _holder.Did, CredentialType,
                new Uri("https://attacker.example/context"), Now, out signer, out subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private Vcdm20VerifierPolicyResult Check(
        string credential, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired, DateTimeOffset now,
        out string signer, out JsonElement claims) =>
        Vcdm20RetiredIssuerVerifier.Check(credential, active, retired,
            _holder.Did, CredentialType, Context, now, out signer, out claims);

    private Vcdm20VerifierPolicyResult CheckWithStatus(
        string credential, string status, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired,
        out string signer, out JsonElement claims) =>
        Vcdm20RetiredIssuerVerifier.CheckWithStatus(credential, status, active, retired,
            _holder.Did, CredentialType, Context, Now, out signer, out claims);

    private void AssertInvalid(string credential, IReadOnlyCollection<string> active,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retired)
    {
        Assert.Equal(Vcdm20VerifierPolicyResult.Invalid,
            Check(credential, active, retired, Now, out string signer, out var subject));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private string Issue((byte[] Seed, string Did) issuer, string membership)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership }));
        return Vcdm20JoseCredential.Create(issuer.Did, _holder.Did,
            CredentialType, Context, document.RootElement, issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private static Vcdm20RetiredCredentialPin Pin(string issuerDid, string jwt) =>
        new(issuerDid, Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(jwt))));

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(issuer.Did, revoked, issuer.Seed, Now,
            new FixedClock(Now));

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var keyWithPrefix = new byte[34];
        keyWithPrefix[0] = 0xed;
        keyWithPrefix[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(keyWithPrefix, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(keyWithPrefix));
    }
}
