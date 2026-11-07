using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Exercises the actual CLI command dispatcher, not a fake signature helper.
/// An issuer signature is not holder key control, revocation or authorization.
/// </summary>
public sealed class CredentialCliIssuerVerificationTests
{
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");

    [Fact]
    public async Task GenuineVc11JwtCanBeCheckedThroughCliWithIndependentIssuerPins()
    {
        var fixture = CreateFixture();
        Assert.Equal(0, await RunAsync(fixture.Jwt, fixture.IssuerDid,
            fixture.HolderDid, CredentialType, Vocabulary));
    }

    [Fact]
    public async Task AnotherGenuineCredentialWithSignedIssuerNameCanBeChecked()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        string jwt = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            document.RootElement, issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(5), "Example Membership Office");
        Assert.Equal(0, await RunAsync(jwt, issuer.Did, holder.Did,
            CredentialType, Vocabulary));
    }

    [Fact]
    public async Task ForgedJwtMustNotBeReportedAsVerified()
    {
        var fixture = CreateFixture();
        string[] pieces = fixture.Jwt.Split('.');
        pieces[1] = pieces[1][..^1] + (pieces[1][^1] == 'A' ? "B" : "A");
        Assert.NotEqual(0, await RunAsync(string.Join('.', pieces),
            fixture.IssuerDid, fixture.HolderDid, CredentialType, Vocabulary));
    }

    [Fact]
    public async Task WrongIssuerHolderOrVocabularyMustFailClosed()
    {
        var fixture = CreateFixture();
        var foreign = NewIdentity();
        Assert.NotEqual(0, await RunAsync(fixture.Jwt, foreign.Did,
            fixture.HolderDid, CredentialType, Vocabulary));
        Assert.NotEqual(0, await RunAsync(fixture.Jwt, fixture.IssuerDid,
            foreign.Did, CredentialType, Vocabulary));
        Assert.NotEqual(0, await RunAsync(fixture.Jwt, fixture.IssuerDid,
            fixture.HolderDid, CredentialType, new Uri("https://issuer.example/wrong")));
    }

    [Fact]
    public async Task ExpiredSignedIssuerJwtMustFailClosed()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        string expired = JwtVcJsonCredential.Create(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            document.RootElement, issuer.Seed, now.AddMinutes(-8),
            now.AddMinutes(-2));
        Assert.NotEqual(0, await RunAsync(expired, issuer.Did,
            holder.Did, CredentialType, Vocabulary));
    }

    [Fact]
    public async Task AbsentIssuerPolicyAndExcessiveInputCannotSucceed()
    {
        var fixture = CreateFixture();
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-issuer"]));
        Assert.NotEqual(0, await RunAsync(new string('A', 65_537),
            fixture.IssuerDid, fixture.HolderDid, CredentialType, Vocabulary));
    }

    [Fact]
    public async Task UnimplementedIssueCommandMustNeverReportSimulatedSuccess()
    {
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["issue"]));
    }

    private static async Task<int> RunAsync(string jwt, string issuer,
        string holder, string credentialType, Uri vocabulary)
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-cli-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(path, jwt);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-issuer", "--jwt-file", path,
                    "--trusted-issuer", issuer, "--holder", holder,
                    "--credential-type", credentialType,
                    "--context", vocabulary.AbsoluteUri]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static (string Jwt, string IssuerDid, string HolderDid) CreateFixture()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active"
        }));
        string jwt = JwtVcJsonCredential.Create(issuer.Did, holder.Did,
            CredentialType, Vocabulary, document.RootElement, issuer.Seed,
            now.AddMinutes(-1), now.AddMinutes(5));
        return (jwt, issuer.Did, holder.Did);
    }

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
