using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20VerifierDenylistTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string CredentialType = "MembershipCredential";

    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _successor = NewIdentity();
    private readonly (byte[] Seed, string Did) _outsider = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void IndependentVerifierAcceptsActiveAndHistoricalIssuerStatementsOnlyWhenPinned()
    {
        string earlier = Issue(_issuer, "member");
        string later = Issue(_successor, "member");

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(earlier, [_issuer.Did, _successor.Did], [], out var firstIssuer, out var firstClaims));
        Assert.Equal(_issuer.Did, firstIssuer);
        Assert.Equal("member", firstClaims.GetProperty("membership").GetString());

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(later, [_issuer.Did, _successor.Did], [], out var secondIssuer, out var secondClaims));
        Assert.Equal(_successor.Did, secondIssuer);
        Assert.Equal("member", secondClaims.GetProperty("membership").GetString());

        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Check(earlier, [_successor.Did], [], out var invalidIssuer, out var invalidClaims),
            invalidIssuer, invalidClaims);
    }

    [Fact]
    public void EmergencyDenyMatchesOnlyTheAuthenticOriginalCompactJwt()
    {
        string denied = Issue(_issuer, "member");
        string allowed = Issue(_issuer, "administrator");
        string deniedDigest = Digest(denied);
        Assert.NotEqual(deniedDigest, Digest(allowed));

        AssertNoClaims(Vcdm20VerifierPolicyResult.DeniedByVerifier,
            Check(denied, [_issuer.Did], [deniedDigest], out var deniedIssuer, out var deniedClaims),
            deniedIssuer, deniedClaims);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedButStatusUnchecked,
            Check(allowed, [_issuer.Did], [deniedDigest], out var allowedIssuer, out var allowedClaims));
        Assert.Equal(_issuer.Did, allowedIssuer);
        Assert.Equal("administrator", allowedClaims.GetProperty("membership").GetString());
    }

    [Fact]
    public void CleanIssuerStatusCannotOverrideLocalDenial()
    {
        string credential = Issue(_issuer, "member");
        string clean = Snapshot(_issuer, []);
        AssertNoClaims(Vcdm20VerifierPolicyResult.DeniedByVerifier,
            CheckWithStatus(credential, clean, [_issuer.Did],
                [Digest(credential)], out var issuer, out var claims), issuer, claims);

        Assert.Equal(Vcdm20VerifierPolicyResult.SignedNotListed,
            CheckWithStatus(credential, clean, [_issuer.Did], [],
                out var trustedIssuer, out var authenticated));
        Assert.Equal(_issuer.Did, trustedIssuer);
        Assert.Equal("member", authenticated.GetProperty("membership").GetString());
    }

    [Fact]
    public void IssuerRevocationAndForeignOrExpiredStatusFailWithoutDisclosure()
    {
        string credential = Issue(_issuer, "member");
        string revoked = Snapshot(_issuer, [credential]);
        AssertNoClaims(Vcdm20VerifierPolicyResult.IssuerReportedRevoked,
            CheckWithStatus(credential, revoked, [_issuer.Did], [],
                out var revokedIssuer, out var revokedClaims), revokedIssuer, revokedClaims);

        string foreign = Snapshot(_outsider, []);
        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            CheckWithStatus(credential, foreign, [_issuer.Did, _outsider.Did], [],
                out var foreignIssuer, out var foreignClaims), foreignIssuer, foreignClaims);

        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20VerifierDenylist.CheckWithStatus(credential, Snapshot(_issuer, []),
                [_issuer.Did], [], _holder.Did, CredentialType, Vocabulary, Now.AddSeconds(61),
                out var staleIssuer, out var staleClaims), staleIssuer, staleClaims);
    }

    [Fact]
    public void MalformedDuplicatedOversizedAndWrongCaseDigestPoliciesFailClosed()
    {
        string credential = Issue(_issuer, "member");
        string digest = Digest(credential);
        string[][] malformed =
        [
            [digest, digest],
            [digest.ToUpperInvariant()],
            ["not-a-sha256"],
            [new string('a', 63)],
            Enumerable.Repeat(digest, 257).ToArray()
        ];
        foreach (string[] deny in malformed)
        {
            AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
                Check(credential, [_issuer.Did], deny, out var issuer, out var claims),
                issuer, claims);
        }

        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Check(credential, [_issuer.Did, _issuer.Did], [],
                out var repeatedIssuer, out var repeatedClaims), repeatedIssuer, repeatedClaims);
    }

    [Fact]
    public void UntrustedForgedExpiredOrWrongHolderTokensCannotBeAuthenticatedByLocalDenial()
    {
        string authentic = Issue(_issuer, "member");
        string outsider = Issue(_outsider, "member");
        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Check(outsider, [_issuer.Did], [Digest(outsider)],
                out var outsiderIssuer, out var outsiderClaims), outsiderIssuer, outsiderClaims);

        string[] pieces = authentic.Split('.');
        pieces[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(authentic)
            .Replace("member", "admin", StringComparison.Ordinal));
        string tampered = string.Join('.', pieces);
        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Check(tampered, [_issuer.Did], [Digest(tampered)],
                out var tamperedIssuer, out var tamperedClaims), tamperedIssuer, tamperedClaims);

        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20VerifierDenylist.Check(authentic, [_issuer.Did], [Digest(authentic)],
                _outsider.Did, CredentialType, Vocabulary, Now,
                out var wrongHolderIssuer, out var wrongHolderClaims),
            wrongHolderIssuer, wrongHolderClaims);

        AssertNoClaims(Vcdm20VerifierPolicyResult.Invalid,
            Vcdm20VerifierDenylist.Check(authentic, [_issuer.Did], [Digest(authentic)],
                _holder.Did, CredentialType, Vocabulary, Now.AddMinutes(20),
                out var expiredIssuer, out var expiredClaims), expiredIssuer, expiredClaims);
    }

    private Vcdm20VerifierPolicyResult Check(
        string jwt, IReadOnlyCollection<string> trusted, IReadOnlyCollection<string> denied,
        out string issuer, out JsonElement claims) =>
        Vcdm20VerifierDenylist.Check(jwt, trusted, denied, _holder.Did,
            CredentialType, Vocabulary, Now, out issuer, out claims);

    private Vcdm20VerifierPolicyResult CheckWithStatus(
        string jwt, string status, IReadOnlyCollection<string> trusted,
        IReadOnlyCollection<string> denied, out string issuer, out JsonElement claims) =>
        Vcdm20VerifierDenylist.CheckWithStatus(jwt, status, trusted, denied,
            _holder.Did, CredentialType, Vocabulary, Now, out issuer, out claims);

    private string Issue((byte[] Seed, string Did) signer, string membership) =>
        Vcdm20JoseCredential.Create(signer.Did, _holder.Did,
            CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = _holder.Did, membership }),
            signer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));

    private static string Snapshot((byte[] Seed, string Did) signer,
        IReadOnlyCollection<string> revoked) =>
        Vcdm20RevocationSnapshot.Create(signer.Did, revoked,
            signer.Seed, Now, new FixedClock(Now));

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

    private static void AssertNoClaims(Vcdm20VerifierPolicyResult expected,
        Vcdm20VerifierPolicyResult actual, string issuer, JsonElement claims)
    {
        Assert.Equal(expected, actual);
        Assert.Equal(string.Empty, issuer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

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
