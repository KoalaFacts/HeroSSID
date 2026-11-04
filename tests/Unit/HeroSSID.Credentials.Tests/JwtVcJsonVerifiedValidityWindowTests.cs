using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>Verified temporal bounds constrain relying-party caching, not business authority.</summary>
public sealed class JwtVcJsonVerifiedValidityWindowTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private const string CredentialType = "MembershipCredential";
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 3, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ExactSignedValidityIsReleasedWithFullOneHundredNanosecondPrecision()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        byte[] seed = issuer.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
                new { id = holderDid, membership = "active" }));
            DateTimeOffset from = Now.AddMinutes(-1).AddTicks(1_234_567);
            DateTimeOffset until = Now.AddMinutes(5).AddTicks(7_654_321);
            string jwt = JwtVcJsonCredential.CreateWithExactValidity(
                issuerDid, holderDid, CredentialType, Vocabulary, subject.RootElement,
                seed, from, until);

            Assert.True(Verify(jwt, issuerDid, holderDid, Now,
                out var claims, out var id, out var issuerName,
                out var verifiedFrom, out var verifiedUntil));
            Assert.Equal("active", claims.GetProperty("membership").GetString());
            Assert.Null(id);
            Assert.Null(issuerName);
            Assert.Equal(from, verifiedFrom);
            Assert.Equal(until, verifiedUntil);

            Assert.False(Verify(jwt, issuerDid, holderDid, until,
                out var expiredClaims, out var expiredId, out var expiredName,
                out var expiredFrom, out var expiredUntil));
            Assert.Equal(JsonValueKind.Undefined, expiredClaims.ValueKind);
            Assert.Null(expiredId);
            Assert.Null(expiredName);
            Assert.Null(expiredFrom);
            Assert.Null(expiredUntil);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    [Fact]
    public void WrongIssuerHolderAndTamperedJwtNeverReleaseSignedTimeBoundaries()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var outsider = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        byte[] seed = issuer.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
                new { id = holderDid, membership = "active" }));
            string jwt = JwtVcJsonCredential.Create(
                issuerDid, holderDid, CredentialType, Vocabulary, subject.RootElement,
                seed, Now.AddMinutes(-1), Now.AddMinutes(5));
            string[] segments = jwt.Split('.');
            segments[1] = Base64UrlEncoder.Encode(
                Ed25519JwtSigner.ExtractPayload(jwt)
                    .Replace("active", "admin", StringComparison.Ordinal));
            foreach (var attempt in new[]
            {
                (Jwt: jwt, Issuer: Did(outsider), Holder: holderDid),
                (Jwt: jwt, Issuer: issuerDid, Holder: Did(outsider)),
                (Jwt: string.Join('.', segments), Issuer: issuerDid, Holder: holderDid)
            })
            {
                Assert.False(Verify(attempt.Jwt, attempt.Issuer, attempt.Holder, Now,
                    out var claims, out var id, out var name, out var from, out var until));
                Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
                Assert.Null(id);
                Assert.Null(name);
                Assert.Null(from);
                Assert.Null(until);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static bool Verify(string jwt, string issuerDid, string holderDid,
        DateTimeOffset at, out JsonElement subject, out string? id, out string? name,
        out DateTimeOffset? validFrom, out DateTimeOffset? validUntil)
    {
        // Reflection permits a test-only branch to compile and fail at runtime
        // before the new public SDK entry point is implemented.
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "TryVerifyWithValidity", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        object?[] arguments =
        [
            jwt, issuerDid, holderDid, CredentialType, Vocabulary, at,
            default(JsonElement), null, null, null, null
        ];
        bool accepted = Assert.IsType<bool>(method.Invoke(null, arguments));
        subject = Assert.IsType<JsonElement>(arguments[6]);
        id = arguments[7] as string;
        name = arguments[8] as string;
        validFrom = arguments[9] is DateTimeOffset from ? from : null;
        validUntil = arguments[10] is DateTimeOffset until ? until : null;
        return accepted;
    }

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string Did(Key key)
    {
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec);
    }
}
