using System.Reflection;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonExactValidityTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/exact-validity/v1");
    private const string CredentialType = "MembershipCredential";

    [Fact]
    public void IssuerCanOptInToExactHundredNanosecondValidityWithoutRoundingAwayTheWindow()
    {
        // Invoke the optional public API by reflection so this test can run
        // against the preceding release and show a genuine runtime RED for
        // the missing issuer capability, rather than a compile-only failure.
        MethodInfo? issueExact = typeof(JwtVcJsonCredential).GetMethod(
            "CreateWithExactValidity", BindingFlags.Public | BindingFlags.Static,
            null,
            [
                typeof(string), typeof(string), typeof(string), typeof(Uri),
                typeof(JsonElement), typeof(byte[]), typeof(DateTimeOffset),
                typeof(DateTimeOffset)
            ],
            null);
        Assert.NotNull(issueExact);

        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset validFrom = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
        validFrom = validFrom.AddTicks(1_234_567);
        DateTimeOffset validUntil = validFrom.AddTicks(7);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));

        string jwt = Assert.IsType<string>(issueExact.Invoke(null,
            [
                issuer.Did, holder.Did, CredentialType, Vocabulary,
                subject.RootElement, issuer.Seed, validFrom, validUntil
            ]));

        using var payloadDocument = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        JsonElement payload = payloadDocument.RootElement;
        decimal expectedFrom = (decimal)(validFrom.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks)
            / TimeSpan.TicksPerSecond;
        decimal expectedUntil = (decimal)(validUntil.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks)
            / TimeSpan.TicksPerSecond;
        Assert.Equal(expectedFrom, payload.GetProperty("nbf").GetDecimal());
        Assert.Equal(expectedFrom, payload.GetProperty("iat").GetDecimal());
        Assert.Equal(expectedUntil, payload.GetProperty("exp").GetDecimal());

        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary, validFrom.AddTicks(-1), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary, validFrom, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary, validUntil.AddTicks(-1), out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary, validUntil, out var expired));
        Assert.Equal(JsonValueKind.Undefined, expired.ValueKind);
    }

    [Fact]
    public void ExactIssuerJtiAndOriginalSignatureRevocationPreserveIssuerTrustBoundary()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        DateTimeOffset start = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
        start = start.AddTicks(1_234_567);
        DateTimeOffset end = start.AddMinutes(10).AddTicks(7);
        var credentialId = new Uri("https://issuer.example/credentials/exact-123");
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { membership = "active" }));
        string jwt = JwtVcJsonCredential.CreateWithExactValidity(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, start, end, credentialId);

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary, start.AddSeconds(1), out var claims,
            out string? signedIdentifier));
        Assert.Equal(credentialId.AbsoluteUri, signedIdentifier);
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, outsider.Did, holder.Did,
            CredentialType, Vocabulary, start.AddSeconds(1), out var foreign,
            out string? foreignIdentifier));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.Null(foreignIdentifier);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, outsider.Did,
            CredentialType, Vocabulary, start.AddSeconds(1), out _));

        DateTimeOffset observedAt = start.AddSeconds(1);
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, [jwt], issuer.Seed, observedAt, new FixedClock(observedAt));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, issuer.Did, observedAt));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, outsider.Did, observedAt));

        string[] components = jwt.Split('.');
        components[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(components[1]).Replace(
                "active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', components),
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            observedAt, out _));
    }

    [Fact]
    public void ExactIssuerRejectsInvalidWindowLongWindowAndWrongIssuerSeed()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        DateTimeOffset start = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
        start = start.AddTicks(9_999_999);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));

        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.CreateWithExactValidity(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, start, start));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.CreateWithExactValidity(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, start, start.AddMinutes(15).AddTicks(1)));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.CreateWithExactValidity(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, outsider.Seed, start, start.AddTicks(1)));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] rawPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        rawPublicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
