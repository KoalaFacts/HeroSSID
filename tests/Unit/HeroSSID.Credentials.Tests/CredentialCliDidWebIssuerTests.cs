using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real issuer-signed VC1.1 did:web JWTs are accepted by the CLI only with
/// pre-enrolled, exact assertion-method/public-key and metadata pins.
/// A matching issuer is not a holder proof or an organisation identity check.
/// </summary>
public sealed class CredentialCliDidWebIssuerTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/1234");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public async Task GenuineIssuerSignedVc11IsAcceptedWithSeparatelyPinnedDidWebKey(string suffix)
    {
        var credential = Issue(suffix);
        Assert.Equal(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary));
    }

    [Fact]
    public async Task OtherIssuerKeyMethodAndSignedMetadataCannotPassVerifierPins()
    {
        var credential = Issue("#key-1");
        var stranger = Identity();
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            stranger.PublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, "did:web:other.example", credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, IssuerDid + "#key-2",
            IssuerName, CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, stranger.Did,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            "Other issuer", CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, new Uri("https://issuer.example/credentials/other"),
            CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, "OtherCredential", Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType,
            new Uri("https://other.example/contexts/membership/v1")));
    }

    [Fact]
    public async Task TamperingAndInvalidPinCannotMakeCliReportSuccessfulVerification()
    {
        var credential = Issue("#key-1");
        string[] pieces = credential.Jwt.Split('.');
        char[] signature = pieces[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        pieces[2] = new string(signature);
        Assert.NotEqual(0, await InvokeAsync(string.Join('.', pieces), credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary,
            keyHexOverride: "00"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.HolderDid,
            credential.IssuerPublicKey, IssuerDid, credential.MethodId,
            IssuerName, CredentialId, CredentialType, Vocabulary,
            keyHexOverride: new string('0', 64)));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc11-didweb-issuer"]));
    }

    private static async Task<int> InvokeAsync(string jwt, string holderDid,
        byte[] issuerPublicKey, string issuerDid, string methodId,
        string issuerName, Uri id, string type, Uri vocabulary,
        string? keyHexOverride = null)
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-didweb-cli-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(path, jwt).ConfigureAwait(false);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-vc11-didweb-issuer", "--jwt-file", path,
                 "--trusted-issuer", issuerDid,
                 "--verification-method", methodId,
                 "--public-key-hex", keyHexOverride ?? Convert.ToHexString(issuerPublicKey),
                 "--issuer-name", issuerName,
                 "--credential-id", id.AbsoluteUri,
                 "--holder", holderDid,
                 "--credential-type", type,
                 "--context", vocabulary.AbsoluteUri]).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static (string Jwt, string HolderDid, byte[] IssuerPublicKey, string MethodId) Issue(string suffix)
    {
        var issuer = Identity();
        var holder = Identity();
        string methodId = IssuerDid + suffix;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string jwt = JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, methodId, issuer.PublicKey, holder.Did, CredentialType,
            Vocabulary, document.RootElement, issuer.Seed,
            now.AddMinutes(-1), now.AddMinutes(5), IssuerName, CredentialId);
        return (jwt, holder.Did, issuer.PublicKey, methodId);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), 
            publicKey, "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
