using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Exercises the real CLI boundary for a recipient-bound, issuer-signed VC2.
/// Issuer authentication is distinct from holder proof and business authority.
/// </summary>
public sealed class CredentialCliVc2RecipientBoundTests
{
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v2");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/42");
    private static readonly Uri OtherId = new("https://issuer.example/credentials/member/43");
    private static readonly Uri Recipient = new("https://verifier.example/checks/membership");
    private static readonly Uri OtherRecipient = new("https://other-verifier.example/checks/membership");

    [Fact]
    public async Task GenuineIssuerSignedRecipientAndCredentialIdSucceed()
    {
        var fixture = CreateFixture(Recipient);
        Assert.Equal(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, CredentialId, Recipient));
    }

    [Fact]
    public async Task GenuineIssuerSignedRecipientJwtWithFinalNewlineSucceed()
    {
        var fixture = CreateFixture(Recipient);
        Assert.Equal(0, await InvokeAsync(fixture.Jwt + "\n", fixture.Issuer,
            fixture.Holder, CredentialId, Recipient));
    }

    [Fact]
    public async Task AnotherGenuineAudienceOrWrongCredentialIdCannotBeAccepted()
    {
        var fixture = CreateFixture(OtherRecipient);
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, CredentialId, Recipient));
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, OtherId, OtherRecipient));
        Assert.Equal(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, CredentialId, OtherRecipient));
    }

    [Fact]
    public async Task CorrectAudienceDoesNotOverrideWrongIssuerOrHolder()
    {
        var fixture = CreateFixture(Recipient);
        string stranger = NewIdentity().Did;
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, stranger,
            fixture.Holder, CredentialId, Recipient));
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            stranger, CredentialId, Recipient));
    }

    [Fact]
    public async Task AudienceFreeDirectVc2AndUnsafeOrMissingPinsFailClosed()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string unbound = Vcdm20JoseCredential.Create(
            issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5));
        Assert.NotEqual(0, await InvokeAsync(unbound, issuer.Did,
            holder.Did, CredentialId, Recipient));
        var fixture = CreateFixture(Recipient);
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, CredentialId, new Uri("http://verifier.example/unsafe")));
        Assert.NotEqual(0, await InvokeAsync(fixture.Jwt, fixture.Issuer,
            fixture.Holder, CredentialId, new Uri("https://user:pass@verifier.example/check")));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-recipient"]));
    }

    [Fact]
    public async Task TamperedSignatureOrExpiredCredentialFailClosed()
    {
        var fixture = CreateFixture(Recipient);
        string[] pieces = fixture.Jwt.Split('.');
        char[] signature = pieces[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        pieces[2] = new string(signature);
        Assert.NotEqual(0, await InvokeAsync(string.Join('.', pieces),
            fixture.Issuer, fixture.Holder, CredentialId, Recipient));

        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string expired = Vcdm20JoseCredential.CreateForAudienceWithId(
            issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-10), now.AddMinutes(-5),
            CredentialId, Recipient);
        Assert.NotEqual(0, await InvokeAsync(expired,
            issuer.Did, holder.Did, CredentialId, Recipient));
    }

    private static async Task<int> InvokeAsync(string jwt, string issuer,
        string holder, Uri id, Uri recipient)
    {
        string file = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-recipient-cli-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(file, jwt).ConfigureAwait(false);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-vc2-recipient", "--jwt-file", file,
                 "--trusted-issuer", issuer, "--holder", holder,
                 "--credential-type", CredentialType, "--context", Context.AbsoluteUri,
                 "--credential-id", id.AbsoluteUri, "--audience", recipient.AbsoluteUri])
                .ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static (string Jwt, string Issuer, string Holder) CreateFixture(Uri recipient)
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var subject = Subject(holder.Did);
        string jwt = Vcdm20JoseCredential.CreateForAudienceWithId(
            issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(5),
            CredentialId, recipient);
        return (jwt, issuer.Did, holder.Did);
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
