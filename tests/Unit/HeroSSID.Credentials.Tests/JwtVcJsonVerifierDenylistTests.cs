using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonVerifierDenylistTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _retired = NewIdentity();
    private readonly (byte[] Seed, string Did) _active = NewIdentity();
    private readonly (byte[] Seed, string Did) _outsider = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void VerifierCanDenyAnExactAuthenticatedActiveOrPinnedRetiredJwt()
    {
        string historical = Issue(_retired, "historical");
        string active = Issue(_active, "active");
        JwtVcJsonRetiredCredentialPin pin = new(_retired.Did, Digest(historical));

        AssertDenied(historical, [_active.Did], [pin], [Digest(historical)]);
        AssertDenied(active, [_active.Did], [pin], [Digest(active)]);

        Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked,
            Check(active, [_active.Did], [pin], [Digest(historical)],
                out string signer, out var claims));
        Assert.Equal(_active.Did, signer);
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked,
            Check(historical, [_active.Did], [pin], [],
                out string retiredSigner, out var retiredClaims));
        Assert.Equal(_retired.Did, retiredSigner);
        Assert.Equal("historical", retiredClaims.GetProperty("membership").GetString());
    }

    [Fact]
    public void CleanIssuerStatusNeverOverridesAnIndependentVerifierDenial()
    {
        string active = Issue(_active, "member");
        string clean = Snapshot(_active, []);
        string revoked = Snapshot(_active, [active]);

        Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedNotListed,
            CheckWithStatus(active, clean, [_active.Did], [], [],
                out string signer, out var claims));
        Assert.Equal(_active.Did, signer);
        Assert.Equal("member", claims.GetProperty("membership").GetString());

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.DeniedByVerifier,
            CheckWithStatus(active, clean, [_active.Did], [], [Digest(active)],
                out string deniedSigner, out var deniedClaims), deniedSigner, deniedClaims);

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.IssuerReportedRevoked,
            CheckWithStatus(active, revoked, [_active.Did], [], [],
                out string revokedSigner, out var revokedClaims), revokedSigner, revokedClaims);

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.Invalid,
            CheckWithStatus(active, Snapshot(_outsider, []), [_active.Did], [],
                [Digest(active)], out string invalidSigner, out var invalidClaims),
            invalidSigner, invalidClaims);
    }

    [Fact]
    public void DuplicatedMalformedAndOversizedDenialPoliciesFailClosedBeforeDisclosure()
    {
        string original = Issue(_active, "member");
        string digest = Digest(original);
        string[][] malformedPolicies =
        [
            [digest, digest],
            [digest, digest.ToUpperInvariant()],
            [digest, "not-a-sha256"],
            [digest, new string('0', 63)],
            Enumerable.Repeat(digest, 257).ToArray()
        ];

        foreach (string[] denied in malformedPolicies)
        {
            AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.Invalid,
                Check(original, [_active.Did], [], denied,
                    out string signer, out var claims), signer, claims);
        }
    }

    [Fact]
    public void LocalPolicyCannotAuthenticateAnOutsiderWrongHolderOrExpiredCredential()
    {
        string outsider = Issue(_outsider, "member");
        string active = Issue(_active, "member");

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.Invalid,
            Check(outsider, [_active.Did], [], [Digest(outsider)],
                out string outsiderSigner, out var outsiderClaims), outsiderSigner, outsiderClaims);

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.Invalid,
            JwtVcJsonVerifierDenylist.Check(active, [_active.Did], [], [Digest(active)],
                _outsider.Did, CredentialType, Vocabulary, Now,
                out string holderSigner, out var holderClaims), holderSigner, holderClaims);

        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.Invalid,
            JwtVcJsonVerifierDenylist.Check(active, [_active.Did], [], [Digest(active)],
                _holder.Did, CredentialType, Vocabulary, Now.AddMinutes(20),
                out string expiredSigner, out var expiredClaims), expiredSigner, expiredClaims);
    }

    [Fact]
    public void DenialMatchesOriginalSignedBytesOnlyNotSimilarClaimsOrKey()
    {
        string original = Issue(_active, "member");
        string changed = Issue(_active, "administrator");
        Assert.NotEqual(Digest(original), Digest(changed));

        Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked,
            Check(changed, [_active.Did], [], [Digest(original)],
                out string signer, out var claims));
        Assert.Equal(_active.Did, signer);
        Assert.Equal("administrator", claims.GetProperty("membership").GetString());

        AssertDenied(original, [_active.Did], [], [Digest(original)]);
        AssertDenied(changed, [_active.Did], [], [Digest(changed)]);
    }

    private void AssertDenied(string jwt, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired, IReadOnlyCollection<string> denied)
    {
        AssertResultNoClaims(JwtVcJsonVerifierPolicyResult.DeniedByVerifier,
            Check(jwt, active, retired, denied, out string signer, out var claims), signer, claims);
    }

    private JwtVcJsonVerifierPolicyResult Check(
        string jwt, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired,
        IReadOnlyCollection<string> denied, out string signer, out JsonElement claims) =>
        JwtVcJsonVerifierDenylist.Check(jwt, active, retired, denied,
            _holder.Did, CredentialType, Vocabulary, Now, out signer, out claims);

    private JwtVcJsonVerifierPolicyResult CheckWithStatus(
        string jwt, string status, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired,
        IReadOnlyCollection<string> denied, out string signer, out JsonElement claims) =>
        JwtVcJsonVerifierDenylist.CheckWithStatus(jwt, status, active, retired,
            denied, _holder.Did, CredentialType, Vocabulary, Now, out signer, out claims);

    private static void AssertResultNoClaims(JwtVcJsonVerifierPolicyResult expected,
        JwtVcJsonVerifierPolicyResult actual, string signer, JsonElement claims)
    {
        Assert.Equal(expected, actual);
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private string Issue((byte[] Seed, string Did) issuer, string membership)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = _holder.Did,
            membership
        }));
        return JwtVcJsonCredential.Create(issuer.Did, _holder.Did,
            CredentialType, Vocabulary, document.RootElement, issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(issuer.Did, revoked,
            issuer.Seed, Now, new FixedClock(Now));

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
