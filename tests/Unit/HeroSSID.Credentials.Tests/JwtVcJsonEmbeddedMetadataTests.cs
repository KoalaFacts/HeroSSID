using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Independently signed VC1.1 JWTs that carry both registered JWT claims and
/// their equivalent VC Data Model fields (REC 6.3.1 "in addition to" mapping).
/// </summary>
public sealed class JwtVcJsonEmbeddedMetadataTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 0, 5, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";
    private const string CredentialId = "https://issuer.example/credentials/member-123";
    private static readonly Uri Vocabulary = new("https://issuer.example/context/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _stranger = NewIdentity();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentIssuerRedundantVcMetadataVerifiesAndRetainsOriginalIssuerStatus(
        bool issuerAsObject)
    {
        string jwt = SignExternal(issuerAsObject);
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject, out var identifier));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.Equal(CredentialId, identifier);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _stranger.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _stranger.Did,
            CredentialType, Vocabulary, Now, out _));

        string revoked = JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
            _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
    }

    [Theory]
    [InlineData("wrong-issuer")]
    [InlineData("wrong-issuer-object")]
    [InlineData("wrong-id")]
    [InlineData("missing-jti")]
    [InlineData("wrong-issuance-date")]
    [InlineData("wrong-expiration-date")]
    [InlineData("unbound-extra-property")]
    [InlineData("legacy-header")]
    [InlineData("wrong-signature")]
    [InlineData("date-only-midnight")]
    [InlineData("subtick-fraction")]
    public void ConflictingOrUnpinnedEmbeddedClaimsNeverReleaseSubject(
        string variant)
    {
        string jwt = SignExternal(variant: variant);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject, out var identifier));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        Assert.Null(identifier);
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
                _issuer.Seed, Now, new FixedClock(Now)));
    }

    [Theory]
    [InlineData("end-of-day")]
    [InlineData("timezone-offset")]
    [InlineData("zero-fraction")]
    public void IndependentIssuerAcceptsExactlyEquivalentXmlDateTimeLexicalForms(string variant)
    {
        string jwt = SignExternal(variant: variant);
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        string revoked = JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
            _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
    }

    [Fact]
    public void TamperedEmbeddedMetadataCannotBeRevalidatedByOriginalSignature()
    {
        string jwt = SignExternal();
        var parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(parts[1]).Replace(
                "member-123", "member-999", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts),
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    private string SignExternal(bool issuerAsObject = false, string? variant = null)
    {
        long notBefore = variant is "end-of-day" or "date-only-midnight"
            ? Now.AddMinutes(-5).ToUnixTimeSeconds()
            : Now.AddMinutes(-1).ToUnixTimeSeconds();
        long expires = Now.AddMinutes(5).ToUnixTimeSeconds();
        var vc = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1", Vocabulary.AbsoluteUri },
            ["type"] = new[] { "VerifiableCredential", CredentialType },
            ["credentialSubject"] = new { membership = "active" },
            ["issuer"] = issuerAsObject ? (object)new { id = _issuer.Did } : _issuer.Did,
            ["id"] = CredentialId,
            ["issuanceDate"] = DateTimeOffset.FromUnixTimeSeconds(notBefore)
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["expirationDate"] = DateTimeOffset.FromUnixTimeSeconds(expires)
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
        };
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer.Did,
            ["sub"] = _holder.Did,
            ["nbf"] = notBefore,
            ["exp"] = expires,
            ["jti"] = CredentialId,
            ["vc"] = vc
        };
        switch (variant)
        {
            case "wrong-issuer":
                vc["issuer"] = _stranger.Did;
                break;
            case "wrong-issuer-object":
                vc["issuer"] = new { id = _stranger.Did };
                break;
            case "wrong-id":
                vc["id"] = "https://issuer.example/credentials/forged";
                break;
            case "missing-jti":
                payload.Remove("jti");
                break;
            case "wrong-issuance-date":
                vc["issuanceDate"] = Now.AddMinutes(-2)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
                break;
            case "wrong-expiration-date":
                vc["expirationDate"] = Now.AddMinutes(6)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
                break;
            case "unbound-extra-property":
                vc["credentialStatus"] = new { id = "https://evil.example/status/1" };
                break;
            case "date-only-midnight":
                vc["issuanceDate"] = "2026-11-04Z";
                break;
            case "subtick-fraction":
                vc["issuanceDate"] = DateTimeOffset.FromUnixTimeSeconds(notBefore)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) +
                    ".000000001Z";
                break;
            case "end-of-day":
                vc["issuanceDate"] = "2026-11-03T24:00:00Z";
                break;
            case "timezone-offset":
                vc["issuanceDate"] = DateTimeOffset.FromUnixTimeSeconds(notBefore)
                    .ToOffset(TimeSpan.FromHours(11))
                    .ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);
                break;
            case "zero-fraction":
                vc["issuanceDate"] = DateTimeOffset.FromUnixTimeSeconds(notBefore)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) +
                    ".000000000Z";
                break;
        }

        string header = variant == "legacy-header"
            ? JsonSerializer.Serialize(new
            {
                alg = "EdDSA", typ = "vc+jwt",
                kid = _issuer.Did + "#" + _issuer.Did["did:key:".Length..]
            })
            : JsonSerializer.Serialize(new { alg = "EdDSA", typ = "JWT" });
        string message = Base64UrlEncoder.Encode(header) + "." +
            Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        using var signer = Key.Import(SignatureAlgorithm.Ed25519,
            variant == "wrong-signature" ? _stranger.Seed : _issuer.Seed,
            KeyBlobFormat.RawPrivateKey);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(
            signer, Encoding.ASCII.GetBytes(message));
        return message + "." + Base64UrlEncoder.Encode(signature);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] raw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        raw.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
