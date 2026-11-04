using System.Reflection;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A relying party with independently enrolled historical/current issuer DIDs
/// can accept one of several explicitly addressed audiences, but must never
/// release subject claims for an outsider, a forged issuer or revoked status.
/// This does not establish holder possession, human consent or business authority.
/// </summary>
public sealed class JwtVcJsonTrustedAudienceVerifierTests
{
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri RecipientA = new("https://a.example/credential-intake");
    private static readonly Uri RecipientB = new("https://b.example/credential-intake");
    private static readonly Uri Outsider = new("https://outsider.example/credential-intake");
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 2, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IndependentlyPinnedHistoricalIssuersAndRecipientsReceiveOriginalSignedClaims()
    {
        var oldIssuer = Identity();
        var currentIssuer = Identity();
        var holder = Identity();
        string jwt = Issue(oldIssuer, holder.Did);
        string[] trusted = [oldIssuer.Did, currentIssuer.Did];

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked,
            Verify("CheckForAudience", jwt, null, trusted, holder.Did, RecipientB,
                null, out string actualIssuer, out var claims));
        Assert.Equal(oldIssuer.Did, actualIssuer);
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Verify("CheckForAudience", jwt, null, trusted, holder.Did, Outsider,
                null, out string outsiderIssuer, out var outsiderClaims));
        Assert.Equal(string.Empty, outsiderIssuer);
        Assert.Equal(JsonValueKind.Undefined, outsiderClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Verify("CheckForAudience", jwt, null, [currentIssuer.Did], holder.Did, RecipientA,
                null, out string retiredIssuer, out var retiredClaims));
        Assert.Equal(string.Empty, retiredIssuer);
        Assert.Equal(JsonValueKind.Undefined, retiredClaims.ValueKind);

        // The legacy trust-list verifier must remain fail-closed for aud.
        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            JwtVcJsonTrustedIssuerVerifier.Check(jwt, trusted, holder.Did,
                CredentialType, Vocabulary, Now, out _, out _));
    }

    [Fact]
    public void RecipientPinnedTrustListRequiresStatusFromActualOriginalSigner()
    {
        var issuer = Identity();
        var otherIssuer = Identity();
        var holder = Identity();
        string jwt = Issue(issuer, holder.Did);
        string[] trusted = [issuer.Did, otherIssuer.Did];
        string clean = Snapshot(issuer, []);
        string wrongSigner = Snapshot(otherIssuer, []);
        string revoked = Snapshot(issuer, [jwt]);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedNotListed,
            Verify("CheckForAudienceWithStatus", jwt, clean, trusted, holder.Did,
                RecipientA, null, out string authenticated, out var claims));
        Assert.Equal(issuer.Did, authenticated);
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        foreach (string untrustedStatus in new[] { wrongSigner, revoked })
        {
            var result = Verify("CheckForAudienceWithStatus", jwt, untrustedStatus, trusted,
                holder.Did, RecipientA, null, out string hiddenIssuer, out var hiddenClaims);
            Assert.True(result is JwtVcJsonTrustedIssuerCheckResult.Invalid
                or JwtVcJsonTrustedIssuerCheckResult.Revoked);
            Assert.Equal(string.Empty, hiddenIssuer);
            Assert.Equal(JsonValueKind.Undefined, hiddenClaims.ValueKind);
        }

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Verify("CheckForAudienceWithStatus", jwt, clean, trusted, holder.Did,
                Outsider, null, out string outsiderIssuer, out var outsiderClaims));
        Assert.Equal(string.Empty, outsiderIssuer);
        Assert.Equal(JsonValueKind.Undefined, outsiderClaims.ValueKind);
    }

    [Fact]
    public void RecipientPinnedIncidentCutoffRejectsOlderGenuineStatus()
    {
        var issuer = Identity();
        var holder = Identity();
        string jwt = Issue(issuer, holder.Did);
        string stale = JwtVcJsonRevocationSnapshot.Create(issuer.Did, [], issuer.Seed,
            Now.AddSeconds(-25), new FixedClock(Now));
        string fresh = Snapshot(issuer, []);
        DateTimeOffset cutoff = Now.AddSeconds(-10);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.Invalid,
            Verify("CheckForAudienceWithStatusAfterObservationCutoff", jwt, stale,
                [issuer.Did], holder.Did, RecipientB, cutoff,
                out string staleIssuer, out var staleClaims));
        Assert.Equal(string.Empty, staleIssuer);
        Assert.Equal(JsonValueKind.Undefined, staleClaims.ValueKind);

        Assert.Equal(JwtVcJsonTrustedIssuerCheckResult.SignedNotListed,
            Verify("CheckForAudienceWithStatusAfterObservationCutoff", jwt, fresh,
                [issuer.Did], holder.Did, RecipientB, cutoff,
                out string freshIssuer, out var freshClaims));
        Assert.Equal(issuer.Did, freshIssuer);
        Assert.Equal("active", freshClaims.GetProperty("membership").GetString());
    }

    private static JwtVcJsonTrustedIssuerCheckResult Verify(
        string methodName, string jwt, string? status, IReadOnlyCollection<string> issuers,
        string holder, Uri audience, DateTimeOffset? cutoff,
        out string signedIssuer, out JsonElement subject)
    {
        // Deliberately compile on old main: the test-only commit must show
        // actual xUnit runtime RED instead of a missing-symbol build failure.
        MethodInfo? method = typeof(JwtVcJsonTrustedIssuerVerifier).GetMethod(
            methodName, BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        var arguments = new List<object?> { jwt };
        if (status is not null)
        {
            arguments.Add(status);
        }
        arguments.AddRange([issuers, holder, CredentialType, Vocabulary, audience, Now]);
        if (cutoff is not null)
        {
            arguments.Add(cutoff.Value);
        }
        arguments.Add(null);
        arguments.Add(default(JsonElement));
        object?[] values = arguments.ToArray();
        var result = Assert.IsType<JwtVcJsonTrustedIssuerCheckResult>(
            method.Invoke(null, values));
        signedIssuer = Assert.IsType<string>(values[^2]);
        subject = Assert.IsType<JsonElement>(values[^1]);
        return result;
    }

    private static string Issue((byte[] Seed, string Did) issuer, string holder)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder, membership = "active" }));
        return JwtVcJsonCredential.CreateForAudiencesWithMetadata(
            issuer.Did, holder, CredentialType, Vocabulary, subject.RootElement,
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            [RecipientA, RecipientB], null, null, exactValidity: true);
    }

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(issuer.Did, revoked,
            issuer.Seed, Now, new FixedClock(Now));

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

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
