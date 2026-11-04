using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Recipient-bound retired issuer credentials require both a verifier-enrolled
/// exact original JWT hash and an independently pinned HTTPS recipient.
/// These tests use real Ed25519 and no external Wallet interoperability.
/// </summary>
public sealed class JwtVcJsonRetiredAudienceVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 0, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "https://issuer.example/credentials#Member";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/credential-intake");
    private static readonly Uri AnotherRecipient = new("https://other.example/credential-intake");
    private static readonly Uri Stranger = new("https://stranger.example/credential-intake");

    [Fact]
    public void PinnedRetiredOriginalAndCurrentIssuerRequireRecipientWhileForgedOldJwtFails()
    {
        var retired = Identity();
        var current = Identity();
        var holder = Identity();
        string historical = Issue(retired, holder.Did, "member");
        string active = Issue(current, holder.Did, "member");
        string forgedAfterRetirement = Issue(retired, holder.Did, "admin");
        var oldPin = Pin(retired.Did, historical);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Verify("CheckForAudience", historical, null, [current.Did], [oldPin],
                holder.Did, Recipient, out string oldIssuer, out var oldClaims));
        Assert.Equal(retired.Did, oldIssuer);
        Assert.Equal("member", oldClaims.GetProperty("role").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Verify("CheckForAudience", active, null, [current.Did], [oldPin],
                holder.Did, AnotherRecipient, out string activeIssuer, out _));
        Assert.Equal(current.Did, activeIssuer);

        foreach (var (jwt, audience, pins) in new[]
        {
            (historical, Stranger, new[] { oldPin }),
            (forgedAfterRetirement, Recipient, new[] { oldPin }),
            (historical, Recipient, Array.Empty<JwtVcJsonRetiredCredentialPin>())
        })
        {
            Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
                Verify("CheckForAudience", jwt, null, [current.Did], pins,
                    holder.Did, audience, out string hiddenIssuer, out var hiddenClaims));
            Assert.Equal(string.Empty, hiddenIssuer);
            Assert.Equal(JsonValueKind.Undefined, hiddenClaims.ValueKind);
        }

        // The old no-audience entry point cannot silently ignore signed aud.
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonRetiredIssuerVerifier.Check(historical, [current.Did], [oldPin],
                holder.Did, CredentialType, Context, Now, out _, out _));
    }

    [Fact]
    public void RetiredRecipientRequiresOriginalSignerStatusAndNeverLeaksOnDenial()
    {
        var retired = Identity();
        var active = Identity();
        var holder = Identity();
        string jwt = Issue(retired, holder.Did, "member");
        JwtVcJsonRetiredCredentialPin pin = Pin(retired.Did, jwt);
        string clean = Snapshot(retired, []);
        string revoked = Snapshot(retired, [jwt]);
        string foreign = Snapshot(active, []);
        string[] trusted = [active.Did];

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedNotListed,
            Verify("CheckForAudienceWithStatus", jwt, clean, trusted, [pin],
                holder.Did, Recipient, out string actualIssuer, out var claims));
        Assert.Equal(retired.Did, actualIssuer);
        Assert.Equal("member", claims.GetProperty("role").GetString());

        foreach (var (status, audience, expected) in new[]
        {
            (revoked, Recipient, JwtVcJsonTrustedIssuerCheckResult.Revoked),
            (foreign, Recipient, JwtVcJsonTrustedIssuerCheckResult.Invalid),
            (clean, Stranger, JwtVcJsonTrustedIssuerCheckResult.Invalid)
        })
        {
            Assert.Equal(expected,
                Verify("CheckForAudienceWithStatus", jwt, status, trusted, [pin],
                    holder.Did, audience, out string hiddenIssuer, out var hiddenClaims));
            Assert.Equal(string.Empty, hiddenIssuer);
            Assert.Equal(JsonValueKind.Undefined, hiddenClaims.ValueKind);
        }

        // Disjoint active/retired roles cannot be bypassed even for signed JWTs.
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Verify("CheckForAudience", jwt, null, [retired.Did], [pin],
                holder.Did, Recipient, out string overlapIssuer, out var overlapClaims));
        Assert.Equal(string.Empty, overlapIssuer);
        Assert.Equal(JsonValueKind.Undefined, overlapClaims.ValueKind);
    }

    private static JwtVcJsonTrustedIssuerCheckResult Verify(string name, string jwt,
        string? snapshot, IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired, string holderDid,
        Uri audience, out string issuer, out JsonElement claims)
    {
        // Test-only source compiles against the old API: missing methods must
        // produce genuine xUnit runtime RED, not missing-symbol build errors.
        MethodInfo? method = typeof(JwtVcJsonRetiredIssuerVerifier).GetMethod(
            name, BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        var inputs = new List<object?> { jwt };
        if (snapshot is not null)
        {
            inputs.Add(snapshot);
        }
        inputs.AddRange([active, retired, holderDid, CredentialType, Context,
            audience, Now, null, default(JsonElement)]);
        object?[] arguments = inputs.ToArray();
        var result = Assert.IsType<JwtVcJsonTrustedIssuerCheckResult>(
            method.Invoke(null, arguments));
        issuer = Assert.IsType<string>(arguments[^2]);
        claims = Assert.IsType<JsonElement>(arguments[^1]);
        return result;
    }

    private static string Issue((byte[] Seed, string Did) identity,
        string holderDid, string role) =>
        JwtVcJsonCredential.CreateForAudiencesWithMetadata(identity.Did, holderDid,
            CredentialType, Context,
            JsonSerializer.SerializeToElement(new { id = holderDid, role }),
            identity.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            [Recipient, AnotherRecipient], null, null, exactValidity: false);

    private static string Snapshot((byte[] Seed, string Did) identity,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(identity.Did, revoked, identity.Seed,
            Now, new Clock());

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static JwtVcJsonRetiredCredentialPin Pin(string did, string jwt) =>
        new(did, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt))));

    private static (byte[] Seed, string Did) Identity()
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
