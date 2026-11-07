using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A relying party must approve its own exact HTTPS recipient before accepting
/// an organisation's independently pinned did:web issuer-signed direct VC2 JWT.
/// Signing alone grants neither holder control nor business authorization.
/// </summary>
public sealed class Vcdm20PinnedDidWebAudienceCliTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/membership/v1");
    private static readonly Uri Id = new("https://issuer.example/credentials/member/1234");
    private static readonly Uri Recipient = new("https://verifier.example/claims/member");
    private static readonly Uri OtherRecipient = new("https://other.example/claims/member");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public async Task GenuineIssuerSignatureAndExactIndependentRecipientPinAreAccepted(string suffix)
    {
        var issued = Issue(suffix, Recipient);
        Assert.Equal(0, await InvokeAsync(issued, Recipient).ConfigureAwait(true));
    }

    [Fact]
    public async Task ValidIssuerSignatureWithWrongRecipientOrKeyIsRejected()
    {
        var issued = Issue("#key-1", OtherRecipient);
        Assert.NotEqual(0, await InvokeAsync(issued, Recipient).ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(issued, OtherRecipient,
            publicKeyHexOverride: new string('0', 64)).ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(issued, OtherRecipient,
            methodOverride: IssuerDid + "#key-2").ConfigureAwait(true));
    }

    [Fact]
    public async Task MissingOrUnsafeRecipientPinAndTamperingNeverAuthenticate()
    {
        var issued = Issue("#key-1", Recipient);
        Assert.NotEqual(0, await InvokeAsync(issued, null).ConfigureAwait(true));
        Assert.NotEqual(0, await InvokeAsync(issued,
            new Uri("http://verifier.example/claims/member")).ConfigureAwait(true));

        string[] parts = issued.Jwt.Split('.');
        char[] sig = parts[2].ToCharArray();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(sig);
        Assert.NotEqual(0, await InvokeAsync(issued with { Jwt = string.Join('.', parts) },
            Recipient).ConfigureAwait(true));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-didweb-issuer"]).ConfigureAwait(true));
    }

    [Fact]
    public void OldIssuerOnlySdkProfileDoesNotSilentlyIgnoreSignedAudience()
    {
        var issued = Issue("#key-1", Recipient);
        Assert.False(Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerNameAndId(
            issued.Jwt, IssuerDid, issued.MethodId, issued.IssuerPublicKey,
            IssuerName, Id, issued.HolderDid, Type, Context,
            DateTimeOffset.UtcNow, out var subject));
        Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
    }

    private static async Task<int> InvokeAsync(
        (string Jwt, string HolderDid, byte[] IssuerPublicKey, string MethodId) issued,
        Uri? audience, string? publicKeyHexOverride = null, string? methodOverride = null)
    {
        string file = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-didweb-aud-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(file, issued.Jwt).ConfigureAwait(true);
            var arguments = new List<string>
            {
                "verify-vc2-didweb-issuer", "--jwt-file", file,
                "--trusted-issuer", IssuerDid, "--verification-method",
                methodOverride ?? issued.MethodId, "--public-key-hex",
                publicKeyHexOverride ?? Convert.ToHexString(issued.IssuerPublicKey),
                "--issuer-name", IssuerName, "--credential-id", Id.AbsoluteUri,
                "--holder", issued.HolderDid, "--credential-type", Type,
                "--context", Context.AbsoluteUri
            };
            if (audience is not null)
            {
                arguments.Add("--audience");
                arguments.Add(audience.AbsoluteUri);
            }

            return await CredentialCommands.CreateCommand(null!)
                .InvokeAsync([.. arguments]).ConfigureAwait(true);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static (string Jwt, string HolderDid, byte[] IssuerPublicKey, string MethodId)
        Issue(string suffix, Uri audience)
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
            ["credentialSubject"] = new { id = holder.Did, membership = "active" },
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
