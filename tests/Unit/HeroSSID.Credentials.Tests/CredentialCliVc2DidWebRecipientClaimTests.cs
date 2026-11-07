using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A relying party can check a genuine did:web issuer statement for its exact
/// recipient and expected membership value without confusing it with authority.
/// The genuine signature and every independently enrolled pin are mandatory.
/// </summary>
public sealed class CredentialCliVc2DidWebRecipientClaimTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/membership/v1");
    private static readonly Uri Id = new("https://issuer.example/credentials/member/1234");
    private static readonly Uri Audience = new("https://verifier.example/membership/admission");
    private static readonly Uri OtherAudience = new("https://other.example/membership/admission");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public async Task GenuineIssuerSignedMembershipForPinnedRecipientIsAccepted(string suffix)
    {
        var credential = Issue(suffix, Audience, "active");
        Assert.Equal(0, await InvokeAsync(credential, Audience, "membership", "active")
            .ConfigureAwait(true));
    }

    [Fact]
    public async Task DifferentRecipientIssuerMethodKeyAndHolderCannotAuthorizeClaim()
    {
        var credential = Issue("#key-1", Audience, "active");
        var stranger = Identity();
        Assert.NotEqual(0, await InvokeAsync(credential, OtherAudience, "membership", "active")
            .ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "active",
            issuerOverride: "did:web:other.example").ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "active",
            methodOverride: IssuerDid + "#key-2").ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "active",
            publicKeyHexOverride: Convert.ToHexString(stranger.PublicKey)).ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "active",
            holderOverride: stranger.Did).ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "active",
            credentialIdOverride: new Uri("https://issuer.example/credentials/member/other"))
            .ConfigureAwait(true));
    }

    [Fact]
    public async Task SignedInactiveMissingOrNonStringClaimDoesNotPassIndependentPolicy()
    {
        var inactive = Issue("#key-1", Audience, "inactive");
        Assert.NotEqual(0, await InvokeAsync(inactive, Audience, "membership", "active")
            .ConfigureAwait(true));
        var number = Issue("#key-1", Audience, 1);
        Assert.NotEqual(0, await InvokeAsync(number, Audience, "membership", "1")
            .ConfigureAwait(true));
        var credential = Issue("#key-1", Audience, "active");
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "role", "admin")
            .ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "id", credential.HolderDid)
            .ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership", "")
            .ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(credential, Audience, "membership",
            "active\nadmin").ConfigureAwait(true));
    }

    [Fact]
    public async Task SignedClaimForOtherRecipientAndTamperedJwtCannotPass()
    {
        var wrongRecipient = Issue("#key-1", OtherAudience, "active");
        Assert.NotEqual(0, await InvokeAsync(wrongRecipient, Audience, "membership", "active")
            .ConfigureAwait(true));
        var issued = Issue("#key-1", Audience, "active");
        var parts = issued.Jwt.Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(signature);
        Assert.NotEqual(0, await InvokeAsync(issued with { Jwt = string.Join('.', parts) },
            Audience, "membership", "active").ConfigureAwait(true));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-didweb-recipient-claim"]).ConfigureAwait(true));
    }

    private static async Task<int> InvokeAsync(
        (string Jwt, string HolderDid, byte[] PublicKey, string MethodId) issued,
        Uri audience, string claimName, string claimValue,
        string? issuerOverride = null, string? methodOverride = null,
        string? publicKeyHexOverride = null, string? holderOverride = null,
        Uri? credentialIdOverride = null)
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-didweb-claim-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(path, issued.Jwt).ConfigureAwait(true);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-vc2-didweb-recipient-claim", "--jwt-file", path,
                 "--trusted-issuer", issuerOverride ?? IssuerDid,
                 "--verification-method", methodOverride ?? issued.MethodId,
                 "--public-key-hex", publicKeyHexOverride ?? Convert.ToHexString(issued.PublicKey),
                 "--issuer-name", IssuerName,
                 "--credential-id", (credentialIdOverride ?? Id).AbsoluteUri,
                 "--audience", audience.AbsoluteUri,
                 "--holder", holderOverride ?? issued.HolderDid,
                 "--credential-type", Type, "--context", Context.AbsoluteUri,
                 "--claim-name", claimName, "--claim-value", claimValue])
                 .ConfigureAwait(true);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static (string Jwt, string HolderDid, byte[] PublicKey, string MethodId)
        Issue(string suffix, Uri audience, object membership)
    {
        var issuer = Identity();
        var holder = Identity();
        string method = IssuerDid + suffix;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        static string Stamp(DateTimeOffset value) =>
            value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2", Context.AbsoluteUri },
            ["type"] = new[] { "VerifiableCredential", Type },
            ["issuer"] = new { id = IssuerDid, name = IssuerName },
            ["validFrom"] = Stamp(now.AddMinutes(-1)),
            ["validUntil"] = Stamp(now.AddMinutes(10)),
            ["credentialSubject"] = new { id = holder.Did, membership },
            ["id"] = Id.AbsoluteUri,
            ["aud"] = audience.AbsoluteUri
        };
        string jwt = Ed25519JwtSigner.CreateSignedJwt(
            JsonSerializer.Serialize(new { alg = "EdDSA", typ = "vc+jwt",
                cty = "vc", kid = method }), JsonSerializer.Serialize(payload), issuer.Seed);
        return (jwt, holder.Did, issuer.PublicKey, method);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
