using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Tests the actual CLI entry point for the W3C VCDM 2.0 direct JOSE
/// profile. Issuer signature alone never proves holder key control.
/// </summary>
public sealed class CredentialCliVc2IssuerVerificationTests
{
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v2");

    [Fact]
    public async Task GenuineDirectVc2JoseWithSeparatelyPinnedIssuerCanBeVerified()
    {
        var fixture = CreateFixture();
        Assert.Equal(0, await InvokeAsync(fixture.Token, fixture.Issuer,
            fixture.Holder, Type, Context));
    }

    [Fact]
    public async Task GenuineVc2FromTextFileWithSingleTrailingNewlineCanBeVerified()
    {
        var fixture = CreateFixture();
        Assert.Equal(0, await InvokeAsync(fixture.Token + "\n", fixture.Issuer,
            fixture.Holder, Type, Context));
    }

    [Fact]
    public async Task WrongIndependentlyPinnedIssuerHolderTypeOrContextFails()
    {
        var fixture = CreateFixture();
        string foreign = NewIdentity().Did;
        Assert.NotEqual(0, await InvokeAsync(fixture.Token, foreign,
            fixture.Holder, Type, Context));
        Assert.NotEqual(0, await InvokeAsync(fixture.Token, fixture.Issuer,
            foreign, Type, Context));
        Assert.NotEqual(0, await InvokeAsync(fixture.Token, fixture.Issuer,
            fixture.Holder, "AdministratorCredential", Context));
        Assert.NotEqual(0, await InvokeAsync(fixture.Token, fixture.Issuer,
            fixture.Holder, Type, new Uri("https://issuer.example/another")));
    }

    [Fact]
    public async Task TamperedDirectVc2ClaimsAreNotAuthenticated()
    {
        var fixture = CreateFixture();
        string[] pieces = fixture.Token.Split('.');
        pieces[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(fixture.Token)
                .Replace("active", "admin", StringComparison.Ordinal));
        Assert.NotEqual(0, await InvokeAsync(string.Join('.', pieces),
            fixture.Issuer, fixture.Holder, Type, Context));
    }

    [Fact]
    public async Task ExpiredGenuinelySignedVc2IsRejected()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string expired = Vcdm20JoseCredential.Create(
            issuer.Did, holder.Did, Type, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-8), now.AddMinutes(-2));
        Assert.NotEqual(0, await InvokeAsync(expired, issuer.Did,
            holder.Did, Type, Context));
    }

    [Fact]
    public async Task GenuineVc2WithUnsupportedStatusFieldIsNotSilentlyAccepted()
    {
        var fixture = CreateFixture();
        string payload = Ed25519JwtSigner.ExtractPayload(fixture.Token);
        string extended = payload.Replace(
            "\"credentialSubject\":",
            "\"credentialStatus\":{\"type\":\"BitstringStatusListEntry\"},\"credentialSubject\":",
            StringComparison.Ordinal);
        Assert.NotEqual(payload, extended);
        string genuinelySigned = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(fixture.Token), extended, fixture.IssuerSeed);
        Assert.NotEqual(0, await InvokeAsync(genuinelySigned,
            fixture.Issuer, fixture.Holder, Type, Context));
    }

    [Fact]
    public async Task Vc11NestedJwtIsNeverAcceptedAsVc2DirectJose()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string legacy = JwtVcJsonCredential.Create(
            issuer.Did, holder.Did, Type, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5));
        Assert.NotEqual(0, await InvokeAsync(legacy, issuer.Did,
            holder.Did, Type, Context));
    }

    [Fact]
    public async Task Vc2DoesNotSlipThroughTheSeparateVc11Command()
    {
        var fixture = CreateFixture();
        Assert.NotEqual(0, await InvokeAsync(fixture.Token, fixture.Issuer,
            fixture.Holder, Type, Context, "verify-issuer"));
    }

    [Fact]
    public async Task MissingPinsOrOversizedInputNeverSucceed()
    {
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-issuer"]));
        var fixture = CreateFixture();
        Assert.NotEqual(0, await InvokeAsync(new string('A', 65_537),
            fixture.Issuer, fixture.Holder, Type, Context));
    }

    private static async Task<int> InvokeAsync(string jwt, string issuer,
        string holder, string type, Uri context, string command = "verify-vc2-issuer")
    {
        string file = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-cli-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(file, jwt).ConfigureAwait(false);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                [command, "--jwt-file", file,
                    "--trusted-issuer", issuer, "--holder", holder,
                    "--credential-type", type,
                    "--context", context.AbsoluteUri]).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static (string Token, string Issuer, string Holder, byte[] IssuerSeed) CreateFixture()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string signed = Vcdm20JoseCredential.Create(
            issuer.Did, holder.Did, Type, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5));
        return (signed, issuer.Did, holder.Did, issuer.Seed);
    }

    private static JsonDocument Subject(string holderDid) =>
        JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holderDid,
            membership = "active"
        }));

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
