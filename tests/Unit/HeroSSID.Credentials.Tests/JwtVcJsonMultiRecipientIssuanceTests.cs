using System.Reflection;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Explicit two-recipient issuance is issuer intent, not holder control,
/// recipient identity, consent, live status or business authorization.
/// </summary>
public sealed class JwtVcJsonMultiRecipientIssuanceTests
{
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri RecipientA = new("https://a.example/credential-intake");
    private static readonly Uri RecipientB = new("https://b.example/credential-intake");
    private static readonly Uri Outsider = new("https://outsider.example/credential-intake");
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";

    [Fact]
    public void OneOriginalIssuerSignedJwtIsUsableOnlyByTwoExplicitlyPinnedRecipients()
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "CreateForAudiencesWithMetadata", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method); // Buildable runtime RED until issuer SDK supports aud arrays.
        string jwt = Assert.IsType<string>(method.Invoke(null,
            [issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                new[] { RecipientA, RecipientB }, null, null, true]));

        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        string[]? audience = document.RootElement.GetProperty("aud")
            .EnumerateArray().Select(static item => item.GetString()).ToArray();
        Assert.Equal([RecipientA.AbsoluteUri, RecipientB.AbsoluteUri], audience);

        Assert.True(JwtVcJsonCredential.TryVerifyForAudience(jwt, issuer.Did, holder.Did,
            CredentialType, Context, RecipientA, Now, out var claimsA));
        Assert.Equal("active", claimsA.GetProperty("membership").GetString());
        Assert.True(JwtVcJsonCredential.TryVerifyForAudience(jwt, issuer.Did, holder.Did,
            CredentialType, Context, RecipientB, Now, out var claimsB));
        Assert.Equal("active", claimsB.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerifyForAudience(jwt, issuer.Did, holder.Did,
            CredentialType, Context, Outsider, Now, out var denied));
        Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Context, Now, out _));
    }

    [Fact]
    public void IssuerRejectsDuplicateInsecureAndAmbiguousRecipientSets()
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holder.Did }));
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "CreateForAudiencesWithMetadata", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        Uri[][] rejected =
        [
            [],
            [RecipientA],
            [RecipientA, RecipientA],
            [RecipientA, new Uri("http://insecure.example/intake")],
            [RecipientA, new Uri("https://user@recipient.example/intake")],
            [RecipientA, new Uri("https://recipient.example/intake#fragment")],
            [RecipientA, new Uri("https://a.example:443/credential-intake")],
            [RecipientA, RecipientB, Outsider, new Uri("https://d.example/"),
                new Uri("https://e.example/"), new Uri("https://f.example/"),
                new Uri("https://g.example/"), new Uri("https://h.example/"),
                new Uri("https://i.example/")]
        ];
        foreach (Uri[] recipients in rejected)
        {
            var error = Assert.Throws<TargetInvocationException>(() => method.Invoke(null,
                [issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
                    issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
                    recipients, null, null, false]));
            Assert.IsType<ArgumentException>(error.InnerException);
        }
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
