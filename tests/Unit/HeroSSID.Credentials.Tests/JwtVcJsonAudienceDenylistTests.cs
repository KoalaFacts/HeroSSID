using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A recipient-pinned relying party must be able to apply its own emergency
/// denylist even to an original VC1.1 JWT with a signed aud restriction.
/// Real independent issuer/holder keys; not Wallet interoperability or consent.
/// </summary>
public sealed class JwtVcJsonAudienceDenylistTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 0, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "https://issuer.example/credentials#Member";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/intake");
    private static readonly Uri AnotherRecipient = new("https://other.example/intake");
    private static readonly Uri OutsiderRecipient = new("https://outsider.example/intake");

    [Fact]
    public void RecipientPinnedActiveAndRetiredCredentialsEnforceIndependentDenials()
    {
        var retired = Identity();
        var active = Identity();
        var holder = Identity();
        string oldJwt = Issue(retired, holder.Did, "member");
        string currentJwt = Issue(active, holder.Did, "member");
        string backdatedNewJwt = Issue(retired, holder.Did, "admin");
        var pin = new JwtVcJsonRetiredCredentialPin(retired.Did, Digest(oldJwt));

        foreach (var (jwt, issuer) in new[]
        {
            (oldJwt, retired.Did),
            (currentJwt, active.Did)
        })
        {
            Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked,
                Verify("CheckForAudience", jwt, null, [active.Did], [pin],
                    [], holder.Did, Recipient, out string actualIssuer, out var claims));
            Assert.Equal(issuer, actualIssuer);
            Assert.Equal("member", claims.GetProperty("role").GetString());

            AssertHidden(JwtVcJsonVerifierPolicyResult.DeniedByVerifier,
                Verify("CheckForAudience", jwt, null, [active.Did], [pin],
                    [Digest(jwt)], holder.Did, Recipient,
                    out string deniedIssuer, out var deniedSubject),
                deniedIssuer, deniedSubject);

            AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
                Verify("CheckForAudience", jwt, null, [active.Did], [pin],
                    [], holder.Did, OutsiderRecipient,
                    out string wrongRecipientIssuer, out var wrongRecipientSubject),
                wrongRecipientIssuer, wrongRecipientSubject);
        }

        AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
            Verify("CheckForAudience", backdatedNewJwt, null, [active.Did], [pin],
                [], holder.Did, Recipient, out string unpinnedIssuer,
                out var unpinnedSubject), unpinnedIssuer, unpinnedSubject);

        AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
            Verify("CheckForAudience", oldJwt, null, [active.Did], [pin],
                [], active.Did, AnotherRecipient, out string wrongHolderIssuer,
                out var wrongHolderSubject), wrongHolderIssuer, wrongHolderSubject);

        // The legacy no-audience route is deliberately fail-closed for aud JWTs.
        AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
            JwtVcJsonVerifierDenylist.Check(currentJwt, [active.Did], [pin],
                [], holder.Did, CredentialType, Context, Now,
                out string legacyIssuer, out var legacySubject),
            legacyIssuer, legacySubject);
    }

    [Fact]
    public void RecipientPinnedStatusCannotOverrideDenialOrUseAnotherSignersSnapshot()
    {
        var issuer = Identity();
        var stranger = Identity();
        var holder = Identity();
        string jwt = Issue(issuer, holder.Did, "member");
        string clean = Snapshot(issuer, []);
        string revoked = Snapshot(issuer, [jwt]);

        Assert.Equal(JwtVcJsonVerifierPolicyResult.SignedNotListed,
            Verify("CheckForAudienceWithStatus", jwt, clean, [issuer.Did], [],
                [], holder.Did, Recipient, out string actualIssuer, out var claims));
        Assert.Equal(issuer.Did, actualIssuer);
        Assert.Equal("member", claims.GetProperty("role").GetString());

        AssertHidden(JwtVcJsonVerifierPolicyResult.DeniedByVerifier,
            Verify("CheckForAudienceWithStatus", jwt, clean, [issuer.Did], [],
                [Digest(jwt)], holder.Did, Recipient, out string deniedIssuer,
                out var deniedSubject), deniedIssuer, deniedSubject);

        AssertHidden(JwtVcJsonVerifierPolicyResult.IssuerReportedRevoked,
            Verify("CheckForAudienceWithStatus", jwt, revoked, [issuer.Did], [],
                [], holder.Did, Recipient, out string revokedIssuer,
                out var revokedSubject), revokedIssuer, revokedSubject);

        AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
            Verify("CheckForAudienceWithStatus", jwt, Snapshot(stranger, []),
                [issuer.Did], [], [], holder.Did, Recipient,
                out string foreignStatusIssuer, out var foreignStatusSubject),
            foreignStatusIssuer, foreignStatusSubject);

        AssertHidden(JwtVcJsonVerifierPolicyResult.Invalid,
            Verify("CheckForAudienceWithStatus", jwt, clean, [issuer.Did], [],
                [Digest(jwt), Digest(jwt)], holder.Did, Recipient,
                out string duplicateIssuer, out var duplicateSubject),
            duplicateIssuer, duplicateSubject);
    }

    private static JwtVcJsonVerifierPolicyResult Verify(
        string methodName, string jwt, string? status,
        IReadOnlyCollection<string> active,
        IReadOnlyCollection<JwtVcJsonRetiredCredentialPin> retired,
        IReadOnlyCollection<string> denied, string holderDid, Uri audience,
        out string issuer, out JsonElement claims)
    {
        // The test-only commit compiles against the old library, so missing
        // implementation produces xUnit runtime RED rather than compile RED.
        MethodInfo? method = typeof(JwtVcJsonVerifierDenylist).GetMethod(
            methodName, BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);

        var args = new List<object?> { jwt };
        if (status is not null)
        {
            args.Add(status);
        }
        args.AddRange([active, retired, denied, holderDid, CredentialType,
            Context, audience, Now, null, default(JsonElement)]);
        object?[] invokeArgs = args.ToArray();
        var result = Assert.IsType<JwtVcJsonVerifierPolicyResult>(
            method.Invoke(null, invokeArgs));
        issuer = Assert.IsType<string>(invokeArgs[^2]);
        claims = Assert.IsType<JsonElement>(invokeArgs[^1]);
        return result;
    }

    private static void AssertHidden(JwtVcJsonVerifierPolicyResult expected,
        JwtVcJsonVerifierPolicyResult actual, string issuer, JsonElement claims)
    {
        Assert.Equal(expected, actual);
        Assert.Equal(string.Empty, issuer);
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private static string Issue((byte[] Seed, string Did) issuer,
        string holderDid, string role) =>
        JwtVcJsonCredential.CreateForAudiencesWithMetadata(
            issuer.Did, holderDid, CredentialType, Context,
            JsonSerializer.SerializeToElement(new { id = holderDid, role }),
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            [Recipient, AnotherRecipient], null, null, exactValidity: false);

    private static string Snapshot((byte[] Seed, string Did) issuer,
        IReadOnlyCollection<string> revoked) =>
        JwtVcJsonRevocationSnapshot.Create(issuer.Did, revoked,
            issuer.Seed, Now, new Clock());

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));

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
