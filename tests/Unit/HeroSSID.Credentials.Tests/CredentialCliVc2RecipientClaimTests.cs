using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// The executable verifier checks one independently required signed string
/// subject claim only after issuer, recipient and ID authentication.
/// No claimant-controlled policy, holder proof or authorization is inferred.
/// </summary>
public sealed class CredentialCliVc2RecipientClaimTests
{
    private const string Type = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v2");
    private static readonly Uri Id = new("https://issuer.example/credentials/member/42");
    private static readonly Uri Audience = new("https://verifier.example/checks/membership");
    private static readonly Uri OtherAudience = new("https://elsewhere.example/checks/membership");

    [Theory]
    [InlineData("membership", "active")]
    [InlineData("tier", "gold")]
    public async Task RealIssuerSignedRequiredClaimIsAccepted(string name, string value)
    {
        var credential = Issue(Audience, Id);
        Assert.Equal(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, name, value));
    }

    [Fact]
    public async Task SignedCredentialCannotPassWrongOrAbsentClaimPolicy()
    {
        var credential = Issue(Audience, Id);
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "membership", "suspended"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "department", "sales"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "memberCount", "2"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "id", credential.Holder));
    }

    [Fact]
    public async Task HolderOrIssuerOrRecipientOrIdMismatchesCannotPassClaim()
    {
        var credential = Issue(Audience, Id);
        string stranger = Identity().Did;
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, stranger,
            credential.Holder, Id, Audience, "membership", "active"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            stranger, Id, Audience, "membership", "active"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, new Uri("https://issuer.example/credentials/member/43"),
            Audience, "membership", "active"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, OtherAudience, "membership", "active"));
    }

    [Fact]
    public async Task ModifiedSignatureAndUnsafeOrEmptyClaimPinsAreRejected()
    {
        var credential = Issue(Audience, Id);
        string[] parts = credential.Jwt.Split('.');
        char[] sig = parts[2].ToCharArray();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(sig);
        Assert.NotEqual(0, await InvokeAsync(string.Join('.', parts),
            credential.Issuer, credential.Holder, Id, Audience, "membership", "active"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "membership", ""));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "membership.name", "active"));
        Assert.NotEqual(0, await InvokeAsync(credential.Jwt, credential.Issuer,
            credential.Holder, Id, Audience, "membership", "active\nadmin"));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-recipient-claim"]));
    }

    [Fact]
    public async Task GenuineIssuerSignedCredentialForOtherRecipientStillFails()
    {
        var other = Issue(OtherAudience, Id);
        Assert.NotEqual(0, await InvokeAsync(other.Jwt, other.Issuer,
            other.Holder, Id, Audience, "membership", "active"));
    }

    private static async Task<int> InvokeAsync(string jwt, string issuer, string holder,
        Uri credentialId, Uri audience, string claimName, string claimValue)
    {
        string file = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-claim-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(file, jwt).ConfigureAwait(false);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-vc2-recipient-claim", "--jwt-file", file,
                 "--trusted-issuer", issuer, "--holder", holder,
                 "--credential-type", Type, "--context", Context.AbsoluteUri,
                 "--credential-id", credentialId.AbsoluteUri,
                 "--audience", audience.AbsoluteUri,
                 "--claim-name", claimName, "--claim-value", claimValue])
                .ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static (string Jwt, string Issuer, string Holder) Issue(Uri recipient, Uri id)
    {
        var issuer = Identity();
        var holder = Identity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = holder.Did,
            membership = "active",
            tier = "gold",
            memberCount = 2
        }));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string jwt = Vcdm20JoseCredential.CreateForAudienceWithId(
            issuer.Did, holder.Did, Type, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(8), id, recipient);
        return (jwt, issuer.Did, holder.Did);
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
