using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonTrustedIssuerVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 10, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "https://example.org/credentials#Member";
    private static readonly Uri Vocabulary = new("https://example.org/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _oldIssuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _newIssuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _outsider = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();

    [Fact]
    public void HistoricalAndCurrentIssuerCredentialsWorkOfflineUntilVerifierRemovesOldTrust()
    {
        string oldJwt = Issue(_oldIssuer);
        string newJwt = Issue(_newIssuer);
        string[] trusted = [_oldIssuer.Did, _newIssuer.Did];

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(oldJwt, trusted, out string oldSigner, out var oldClaims));
        Assert.Equal(_oldIssuer.Did, oldSigner);
        Assert.Equal("active", oldClaims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Check(newJwt, trusted, out string newSigner, out var newClaims));
        Assert.Equal(_newIssuer.Did, newSigner);
        Assert.Equal("active", newClaims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Check(oldJwt, [_newIssuer.Did], out string rejectedSigner, out var rejectedClaims));
        Assert.Equal(string.Empty, rejectedSigner);
        Assert.Equal(JsonValueKind.Undefined, rejectedClaims.ValueKind);
    }

    [Fact]
    public void ARealSignatureFromAnUntrustedIssuerAndAlteredJwtNeverDiscloseClaims()
    {
        string rogueJwt = Issue(_outsider);
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Check(rogueJwt, [_oldIssuer.Did, _newIssuer.Did],
                out string rogueSigner, out var rogueClaims));
        Assert.Equal(string.Empty, rogueSigner);
        Assert.Equal(JsonValueKind.Undefined, rogueClaims.ValueKind);

        string oldJwt = Issue(_oldIssuer);
        string[] pieces = oldJwt.Split('.');
        pieces[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(oldJwt).Replace("active", "admin", StringComparison.Ordinal));
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Check(string.Join('.', pieces), [_oldIssuer.Did],
                out string alteredSigner, out var alteredClaims));
        Assert.Equal(string.Empty, alteredSigner);
        Assert.Equal(JsonValueKind.Undefined, alteredClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonTrustedIssuerVerifier.Check(oldJwt, [_oldIssuer.Did],
                _outsider.Did, CredentialType, Vocabulary, Now,
                out string wrongHolderSigner, out var wrongHolderClaims));
        Assert.Equal(string.Empty, wrongHolderSigner);
        Assert.Equal(JsonValueKind.Undefined, wrongHolderClaims.ValueKind);
    }

    [Fact]
    public void CompactCredentialTypeMustNotBypassTheExpandedHttpsVerifierPolicy()
    {
        // The lower-level VC1.1 primitive permits a custom compact term when
        // the caller pins its context. This offline verifier intentionally
        // requires an expanded HTTPS IRI, as does the non-.NET HTTP adapter.
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string compact = JwtVcJsonCredential.Create(_oldIssuer.Did, _holder.Did,
            "Member", Vocabulary, subject.RootElement, _oldIssuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
        Assert.True(JwtVcJsonCredential.TryVerify(compact, _oldIssuer.Did,
            _holder.Did, "Member", Vocabulary, Now, out _));
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonTrustedIssuerVerifier.Check(compact, [_oldIssuer.Did],
                _holder.Did, "Member", Vocabulary, Now,
                out string signer, out var claims));
        Assert.Equal(string.Empty, signer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    [Fact]
    public void CleanSameSignerSnapshotAuthenticatesOnlyTheActualIssuer()
    {
        string original = Issue(_oldIssuer);
        string cleanOld = Snapshot(_oldIssuer, []);
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedNotListed,
            CheckWithStatus(original, cleanOld, [_oldIssuer.Did, _newIssuer.Did],
                out string realSigner, out var claims));
        Assert.Equal(_oldIssuer.Did, realSigner);
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        string cleanNew = Snapshot(_newIssuer, []);
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            CheckWithStatus(original, cleanNew, [_oldIssuer.Did, _newIssuer.Did],
                out string rejectedSigner, out var rejectedClaims));
        Assert.Equal(string.Empty, rejectedSigner);
        Assert.Equal(JsonValueKind.Undefined, rejectedClaims.ValueKind);
    }

    [Fact]
    public void RevokedExpiredAndMissingStatusNeverLeakTheAuthenticatedSignerOrSubject()
    {
        string original = Issue(_oldIssuer);
        string revoked = Snapshot(_oldIssuer, [original]);
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Revoked,
            CheckWithStatus(original, revoked, [_oldIssuer.Did],
                out string revokedSigner, out var revokedClaims));
        Assert.Equal(string.Empty, revokedSigner);
        Assert.Equal(JsonValueKind.Undefined, revokedClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonTrustedIssuerVerifier.CheckWithStatus(
                original, revoked, [_oldIssuer.Did], _holder.Did, CredentialType,
                Vocabulary, Now.AddMinutes(2), out string expiredSigner, out var expiredClaims));
        Assert.Equal(string.Empty, expiredSigner);
        Assert.Equal(JsonValueKind.Undefined, expiredClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            CheckWithStatus(original, string.Empty, [_oldIssuer.Did],
                out string missingSigner, out var missingClaims));
        Assert.Equal(string.Empty, missingSigner);
        Assert.Equal(JsonValueKind.Undefined, missingClaims.ValueKind);
    }

    [Fact]
    public void DuplicateInvalidEmptyAndUnboundedIssuerPoliciesFailClosedBeforeDisclosure()
    {
        string original = Issue(_oldIssuer);
        string[][] policies =
        [
            [],
            [_oldIssuer.Did, _oldIssuer.Did],
            [_oldIssuer.Did, "did:key:znot-a-key"],
            Enumerable.Repeat(_oldIssuer.Did, 17).ToArray()
        ];

        foreach (string[] trusted in policies)
        {
            Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
                Check(original, trusted, out string signer, out var subject));
            Assert.Equal(string.Empty, signer);
            Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        }
    }

    private JwtVcJsonTrustedIssuerCheckResult Check(
        string jwt, IReadOnlyCollection<string> issuers,
        out string signer, out JsonElement subject) =>
        JwtVcJsonTrustedIssuerVerifier.Check(jwt, issuers, _holder.Did,
            CredentialType, Vocabulary, Now, out signer, out subject);

    private JwtVcJsonTrustedIssuerCheckResult CheckWithStatus(
        string jwt, string status, IReadOnlyCollection<string> issuers,
        out string signer, out JsonElement subject) =>
        JwtVcJsonTrustedIssuerVerifier.CheckWithStatus(jwt, status, issuers, _holder.Did,
            CredentialType, Vocabulary, Now, out signer, out subject);

    private string Issue((byte[] Seed, string Did) issuer)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return JwtVcJsonCredential.Create(issuer.Did, _holder.Did, CredentialType,
            Vocabulary, subject.RootElement, issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10));
    }

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
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
