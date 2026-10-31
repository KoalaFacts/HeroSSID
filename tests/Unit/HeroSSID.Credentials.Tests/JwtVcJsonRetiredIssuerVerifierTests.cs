using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonRetiredIssuerVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _oldIssuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _activeIssuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _outsider = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void PreviouslyRegisteredOldCredentialAndNewActiveIssuerBothVerify()
    {
        string historical = Issue(_oldIssuer, "member");
        string current = Issue(_activeIssuer, "member");
        JwtVcJsonRetiredCredentialPin pin = Pin(_oldIssuer.Did, historical);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(historical, [_activeIssuer.Did], [pin],
                out string originalIssuer, out var historicalClaims));
        Assert.Equal(_oldIssuer.Did, originalIssuer);
        Assert.Equal("member", historicalClaims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(current, [_activeIssuer.Did], [pin],
                out string currentIssuer, out var currentClaims));
        Assert.Equal(_activeIssuer.Did, currentIssuer);
        Assert.Equal("member", currentClaims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(historical, [], [pin], out string retiredOnlyIssuer, out _));
        Assert.Equal(_oldIssuer.Did, retiredOnlyIssuer);
    }

    [Fact]
    public void RetiredIssuerCannotIssueFreshBackdatedCredentialEvenWithRealOldSigningKey()
    {
        string historical = Issue(_oldIssuer, "member");
        string maliciousBackdated = Issue(_oldIssuer, "administrator");
        Assert.NotEqual(historical, maliciousBackdated);
        Assert.True(JwtVcJsonCredential.TryVerify(maliciousBackdated, _oldIssuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));

        AssertInvalid(maliciousBackdated, [_activeIssuer.Did],
            [Pin(_oldIssuer.Did, historical)]);
        AssertInvalid(historical, [_activeIssuer.Did], []);
        AssertInvalid(Issue(_outsider, "member"), [_activeIssuer.Did],
            [Pin(_oldIssuer.Did, historical)]);

        // A verifier may independently and deliberately enroll another exact
        // historic artifact, but no untrusted JWT header or iat enrolls it.
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(maliciousBackdated, [_activeIssuer.Did],
                [Pin(_oldIssuer.Did, maliciousBackdated)], out string signer, out _));
        Assert.Equal(_oldIssuer.Did, signer);
    }

    [Fact]
    public void InvalidOrOverlappingRetirementPolicyFailsClosedBeforeAnyClaims()
    {
        string oldJwt = Issue(_oldIssuer, "member");
        string currentJwt = Issue(_activeIssuer, "member");
        JwtVcJsonRetiredCredentialPin oldPin = Pin(_oldIssuer.Did, oldJwt);
        JwtVcJsonRetiredCredentialPin currentPin = Pin(_activeIssuer.Did, currentJwt);

        AssertInvalid(currentJwt, [_activeIssuer.Did], [currentPin]);
        AssertInvalid(currentJwt, [_activeIssuer.Did], [oldPin, oldPin]);
        AssertInvalid(currentJwt, [_activeIssuer.Did],
            [new JwtVcJsonRetiredCredentialPin(_oldIssuer.Did, "not-a-sha256")]);
        AssertInvalid(currentJwt, [_activeIssuer.Did],
            [new JwtVcJsonRetiredCredentialPin("did:key:invalid", oldPin.CredentialSha256)]);
        AssertInvalid(currentJwt, [_activeIssuer.Did, _activeIssuer.Did], [oldPin]);
        AssertInvalid(currentJwt, [], []);

        // Even a genuine issuer signature must not make an unvalidated later
        // policy entry invisible to the verifier.
        AssertInvalid(currentJwt, [_activeIssuer.Did],
            Enumerable.Repeat(oldPin, 257).ToArray());
        AssertInvalid(currentJwt, Enumerable.Repeat(_activeIssuer.Did, 17).ToArray(), []);
    }

    [Fact]
    public void SameIssuerStatusRemainsMandatoryAndRevokedOrForeignStatusLeaksNothing()
    {
        string historical = Issue(_oldIssuer, "member");
        JwtVcJsonRetiredCredentialPin pin = Pin(_oldIssuer.Did, historical);
        string clean = Snapshot(_oldIssuer, []);
        string revoked = Snapshot(_oldIssuer, [historical]);
        string foreign = Snapshot(_activeIssuer, []);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedNotListed,
            CheckWithStatus(historical, clean, [_activeIssuer.Did], [pin],
                out string signer, out var subject));
        Assert.Equal(_oldIssuer.Did, signer);
        Assert.Equal("member", subject.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Revoked,
            CheckWithStatus(historical, revoked, [_activeIssuer.Did], [pin],
                out string revokedSigner, out var revokedClaims));
        Assert.Equal(string.Empty, revokedSigner);
        Assert.Equal(JsonValueKind.Undefined, revokedClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            CheckWithStatus(historical, foreign, [_activeIssuer.Did], [pin],
                out string foreignSigner, out var foreignClaims));
        Assert.Equal(string.Empty, foreignSigner);
        Assert.Equal(JsonValueKind.Undefined, foreignClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonRetiredIssuerVerifier.Check(historical, [_activeIssuer.Did], [pin],
                _holder.Did, CredentialType, Vocabulary, Now.AddMinutes(20),
                out string expiredSigner, out var expiredClaims));
        Assert.Equal(string.Empty, expiredSigner);
        Assert.Equal(JsonValueKind.Undefined, expiredClaims.ValueKind);
    }

    private JwtVcJsonTrustedIssuerCheckResult Check(
        string credential, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired,
        out string signer, out JsonElement claims) =>
        JwtVcJsonRetiredIssuerVerifier.Check(credential, active, retired,
            _holder.Did, CredentialType, Vocabulary, Now, out signer, out claims);

    private JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string credential, string snapshot, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired,
        out string signer, out JsonElement claims) =>
        JwtVcJsonRetiredIssuerVerifier.CheckWithStatus(credential, snapshot, active,
            retired, _holder.Did, CredentialType, Vocabulary, Now, out signer, out claims);

    private void AssertInvalid(string credential, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired)
    {
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Check(credential, active, retired, out string signer, out var claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private string Issue((byte[] Seed, string Did) issuer, string membership)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _holder.Did,
            membership
        }));
        return JwtVcJsonCredential.Create(issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private static JwtVcJsonRetiredCredentialPin Pin(string did, string signedJwt) =>
        new(did, Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(signedJwt))));

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(issuer.Did, revoked, issuer.Seed,
            Now, new FixedClock(Now));

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
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
