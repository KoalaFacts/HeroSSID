using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A real issuer must be able to produce an authentic direct VC2 JWT that the
/// independent relying-party pin verifier accepts without handcrafted JOSE.
/// </summary>
public sealed class Vcdm20PinnedDidWebIssuerIssuanceTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/vocab/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/1234");
    private static readonly Uri Audience = new("https://verifier.example/membership");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public void GenuinelyIssuedRecipientCredentialPassesIndependentVerifier(string methodSuffix)
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string method = IssuerDid + methodSuffix;

        string jwt = Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
            IssuerDid, method, issuer.Seed, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holder.Did, Type, Context,
            subject.RootElement, now.AddMinutes(-1), now.AddMinutes(10));

        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        Assert.Equal(method, header.RootElement.GetProperty("kid").GetString());
        Assert.Equal("vc+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.True(Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
            jwt, IssuerDid, method, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holder.Did, Type, Context, now,
            out var accepted));
        Assert.Equal("active", accepted.GetProperty("membership").GetString());
    }


    [Fact]
    public void IssuerCannotIssueWithWrongSeedMethodOrUnsafeBoundaries()
    {
        var issuer = Identity();
        var impostor = Identity();
        var holder = Identity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        string Issue(string method, byte[] seed, byte[] publicKey, Uri audience,
            DateTimeOffset from, DateTimeOffset until, JsonElement data) =>
            Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
                IssuerDid, method, seed, publicKey, IssuerName,
                CredentialId, audience, holder.Did, Type, Context, data, from, until);

        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-1", impostor.Seed, issuer.PublicKey,
            Audience, now.AddMinutes(-1), now.AddMinutes(10), subject.RootElement));
        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-1", issuer.Seed, impostor.PublicKey,
            Audience, now.AddMinutes(-1), now.AddMinutes(10), subject.RootElement));
        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-3", issuer.Seed, issuer.PublicKey,
            Audience, now.AddMinutes(-1), now.AddMinutes(10), subject.RootElement));
        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey,
            new Uri("http://verifier.example/membership"),
            now.AddMinutes(-1), now.AddMinutes(10), subject.RootElement));
        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey,
            Audience, now.AddMinutes(10), now.AddMinutes(1), subject.RootElement));

        using var noHolderId = JsonDocument.Parse("{\"membership\":\"active\"}");
        Assert.Throws<ArgumentException>(() => Issue(
            IssuerDid + "#key-1", issuer.Seed, issuer.PublicKey,
            Audience, now.AddMinutes(-1), now.AddMinutes(10), noHolderId.RootElement));
    }

    [Fact]
    public async Task IssuedArtifactWorksWithExistingRecipientClaimCliButWrongPolicyFails()
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string method = IssuerDid + "#key-2";
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        string jwt = Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
            IssuerDid, method, issuer.Seed, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holder.Did, Type, Context, subject.RootElement,
            now.AddMinutes(-1), now.AddMinutes(10));
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-issued-vc2-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(path, jwt).ConfigureAwait(true);
            string[] options =
            [
                "verify-vc2-didweb-recipient-claim", "--jwt-file", path,
                "--trusted-issuer", IssuerDid,
                "--verification-method", method,
                "--public-key-hex", Convert.ToHexString(issuer.PublicKey),
                "--issuer-name", IssuerName,
                "--credential-id", CredentialId.AbsoluteUri,
                "--audience", Audience.AbsoluteUri,
                "--holder", holder.Did,
                "--credential-type", Type,
                "--context", Context.AbsoluteUri,
                "--claim-name", "membership",
                "--claim-value", "active"
            ];
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(options).ConfigureAwait(true));
            options[^1] = "admin";
            Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(options).ConfigureAwait(true));

            Assert.False(Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
                jwt, IssuerDid, method, issuer.PublicKey, IssuerName,
                CredentialId, new Uri("https://other.example/membership"),
                holder.Did, Type, Context, now, out JsonElement denied));
            Assert.Equal(JsonValueKind.Undefined, denied.ValueKind);
        }
        finally
        {
            File.Delete(path);
        }
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
