using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20DidKeyStatusVerifierCliTests
{
    private const string CredentialType = "RoleCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/role/v1");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OriginalIssuerSignedCredentialAndStatusAreCheckedTogether(bool revoked)
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string credential = Issue(issuer, holder, now);
        string snapshot = Vcdm20RevocationSnapshot.Create(issuer.Did,
            revoked ? [credential] : [], issuer.Seed, now, TimeProvider.System);
        string directory = TemporaryDirectory();
        try
        {
            var (jwtFile, statusFile) = Write(directory, credential, snapshot);
            var pins = Pins(jwtFile, statusFile, issuer.Did, holder.Did, now.AddSeconds(-5));
            Assert.Equal(!revoked, CredentialCommands.TryVerifyVc2DidKeyStatus(pins, now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void VerifierOwnedObservationCutoffRejectsEarlierAuthenticStatus()
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string credential = Issue(issuer, holder, now);
        string snapshot = Vcdm20RevocationSnapshot.Create(issuer.Did,
            [], issuer.Seed, now, TimeProvider.System);
        string directory = TemporaryDirectory();
        try
        {
            var (jwtFile, statusFile) = Write(directory, credential, snapshot);
            DateTimeOffset signedSecond = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
            Assert.True(CredentialCommands.TryVerifyVc2DidKeyStatus(
                Pins(jwtFile, statusFile, issuer.Did, holder.Did, signedSecond), now));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyStatus(
                Pins(jwtFile, statusFile, issuer.Did, holder.Did, signedSecond.AddTicks(1)),
                now.AddSeconds(1)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void SignatureMismatchHolderMismatchAndAlteredOriginalFailClosed()
    {
        var issuer = Identity();
        var another = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string credential = Issue(issuer, holder, now);
        string snapshot = Vcdm20RevocationSnapshot.Create(issuer.Did,
            [], issuer.Seed, now, TimeProvider.System);
        string directory = TemporaryDirectory();
        try
        {
            var (jwtFile, statusFile) = Write(directory, credential, snapshot);
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyStatus(
                Pins(jwtFile, statusFile, another.Did, holder.Did, now.AddSeconds(-1)), now));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyStatus(
                Pins(jwtFile, statusFile, issuer.Did, another.Did, now.AddSeconds(-1)), now));
            File.WriteAllText(jwtFile, credential[..^1] + (credential[^1] == 'A' ? "B" : "A") + "\n");
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyStatus(
                Pins(jwtFile, statusFile, issuer.Did, holder.Did, now.AddSeconds(-1)), now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task OperatorCliAcceptsOnlyIndependentlyPinnedOriginals()
    {
        var issuer = Identity();
        var holder = Identity();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string credential = Issue(issuer, holder, now);
        string snapshot = Vcdm20RevocationSnapshot.Create(issuer.Did,
            [], issuer.Seed, now, TimeProvider.System);
        string directory = TemporaryDirectory();
        try
        {
            var (jwtFile, statusFile) = Write(directory, credential, snapshot);
            string[] args =
            [
                "verify-vc2-didkey-status", "--jwt-file", jwtFile,
                "--snapshot-file", statusFile, "--trusted-issuer", issuer.Did,
                "--holder", holder.Did, "--credential-type", CredentialType,
                "--context", Context.AbsoluteUri, "--minimum-observed-at",
                now.AddSeconds(-5).ToString("O")
            ];
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!).InvokeAsync(args));
            args[^1] = now.AddSeconds(5).ToString("O");
            Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!).InvokeAsync(args));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc2DidKeyStatusVerifyParameters Pins(
        string jwtFile, string statusFile, string issuerDid, string holderDid,
        DateTimeOffset cutoff) =>
        new(jwtFile, statusFile, issuerDid, holderDid,
            CredentialType, Context.AbsoluteUri, cutoff.ToString("O"));

    private static (string JwtFile, string StatusFile) Write(
        string directory, string credential, string snapshot)
    {
        string jwtFile = Path.Combine(directory, "issued.jwt");
        string statusFile = Path.Combine(directory, "status.jwt");
        File.WriteAllText(jwtFile, credential + "\n");
        File.WriteAllText(statusFile, snapshot + "\n");
        return (jwtFile, statusFile);
    }

    private static string Issue((byte[] Seed, string Did) issuer,
        (byte[] Seed, string Did) holder, DateTimeOffset now) =>
        Vcdm20JoseCredential.Create(issuer.Did, holder.Did, CredentialType,
            Context, JsonSerializer.SerializeToElement(
                new { id = holder.Did, role = "member" }),
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(10));

    private static string TemporaryDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-didkey-status-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
