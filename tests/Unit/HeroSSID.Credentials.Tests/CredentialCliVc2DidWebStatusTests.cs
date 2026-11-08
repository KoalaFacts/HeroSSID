using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A non-.NET relying party can check the original VC2 issuer signature AND
/// the issuer's separate signed status observation through the offline CLI.
/// This does not establish holder key control or business authority.
/// </summary>
public sealed class CredentialCliVc2DidWebStatusTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/42");
    private static readonly Uri Audience = new("https://verifier.example/check");
    private static readonly Uri Context = new("https://issuer.example/vocab/member");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public async Task AuthenticStatusForPinnedIssuerAndOriginalJwtIsAccepted(string suffix)
    {
        var sample = IssueAndObserve(suffix, revoked: false);
        Assert.Equal(0, await VerifyAsync(sample).ConfigureAwait(true));
    }

    [Fact]
    public async Task RevocationAndUntrustedKeysOrRecipientsAreRejected()
    {
        var revoked = IssueAndObserve("#key-1", revoked: true);
        Assert.NotEqual(0, await VerifyAsync(revoked).ConfigureAwait(true));

        var sample = IssueAndObserve("#key-1", revoked: false);
        var attacker = Identity();
        Assert.NotEqual(0, await VerifyAsync(sample,
            publicKeyOverride: Convert.ToHexString(attacker.PublicKey)).ConfigureAwait(true));
        Assert.NotEqual(0, await VerifyAsync(sample,
            audienceOverride: "https://wrong.example/check").ConfigureAwait(true));
        Assert.NotEqual(0, await VerifyAsync(sample,
            methodOverride: IssuerDid + "#key-2").ConfigureAwait(true));
        Assert.NotEqual(0, await VerifyAsync(sample,
            holderOverride: attacker.Did).ConfigureAwait(true));
        Assert.NotEqual(0, await VerifyAsync(sample,
            credentialIdOverride: "https://issuer.example/credentials/other").ConfigureAwait(true));
    }

    [Fact]
    public async Task AlteredSnapshotJwtAndInsufficientObservationCannotBeAccepted()
    {
        var sample = IssueAndObserve("#key-1", revoked: false);
        string[] parts = sample.Status.Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(signature);
        Assert.NotEqual(0, await VerifyAsync(sample with { Status = string.Join('.', parts) })
            .ConfigureAwait(true));

        // The cutoff belongs to the relying verifier, not to the JWT or status.
        Assert.NotEqual(0, await VerifyAsync(sample,
            minimumObservedOverride: DateTimeOffset.UtcNow.AddMinutes(1))
            .ConfigureAwait(true));
        Assert.NotEqual(0, await VerifyAsync(sample,
            minimumObservedOverride: DateTimeOffset.UtcNow.AddSeconds(-1))
            .ConfigureAwait(true));

        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(["verify-vc2-didweb-status"]).ConfigureAwait(true));
    }

    private static async Task<int> VerifyAsync(
        Sample sample, string? publicKeyOverride = null,
        string? audienceOverride = null, string? methodOverride = null,
        string? holderOverride = null, string? credentialIdOverride = null,
        DateTimeOffset? minimumObservedOverride = null)
    {
        string jwtPath = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-status-credential-" + Guid.NewGuid().ToString("N") + ".jwt");
        string statusPath = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-status-snapshot-" + Guid.NewGuid().ToString("N") + ".jwt");
        try
        {
            await File.WriteAllTextAsync(jwtPath, sample.Jwt).ConfigureAwait(true);
            await File.WriteAllTextAsync(statusPath, sample.Status).ConfigureAwait(true);
            return await CredentialCommands.CreateCommand(null!).InvokeAsync(
                ["verify-vc2-didweb-status", "--jwt-file", jwtPath,
                 "--snapshot-file", statusPath, "--trusted-issuer", IssuerDid,
                 "--verification-method", methodOverride ?? sample.Method,
                 "--public-key-hex", publicKeyOverride ?? Convert.ToHexString(sample.PublicKey),
                 "--issuer-name", IssuerName, "--credential-id",
                 credentialIdOverride ?? CredentialId.AbsoluteUri,
                 "--audience", audienceOverride ?? Audience.AbsoluteUri,
                 "--holder", holderOverride ?? sample.Holder,
                 "--credential-type", "MembershipCredential",
                 "--context", Context.AbsoluteUri,
                 "--minimum-observed-at",
                 (minimumObservedOverride ?? sample.Cutoff).ToString("O", CultureInfo.InvariantCulture)])
                .ConfigureAwait(true);
        }
        finally
        {
            File.Delete(jwtPath);
            File.Delete(statusPath);
        }
    }

    private static Sample IssueAndObserve(string suffix, bool revoked)
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string method = IssuerDid + suffix;
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        string credential = Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
            IssuerDid, method, issuer.Seed, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holder.Did, "MembershipCredential",
            Context, subject.RootElement, now.AddMinutes(-1), now.AddMinutes(10));
        string status = Vcdm20PinnedDidWebIssuerStatus.Create(
            IssuerDid, method, issuer.Seed, issuer.PublicKey, IssuerName,
            revoked ? [credential] : [], now.AddSeconds(-3), TimeProvider.System);
        return new Sample(credential, status, holder.Did, issuer.PublicKey, method,
            now.AddSeconds(-5));
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed record Sample(
        string Jwt, string Status, string Holder, byte[] PublicKey,
        string Method, DateTimeOffset Cutoff);
}
