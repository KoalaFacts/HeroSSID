using System.CommandLine;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20DidKeyIssuerCliIssuanceTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/vocab/role");

    [Fact]
    public async Task RedirectedIssuerSeedProducesRealDirectVc2AcceptedByIndependentPinnedVerifier()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            await File.WriteAllTextAsync(subject,
                JsonSerializer.Serialize(new { id = holder.Did, role = "member" }));
            string output = Path.Combine(directory, "issued.jwt");
            using var pipe = Pipe(issuer.Seed);
            Assert.True(CredentialCommands.TryIssueVc2DidKey(
                Request(issuer.Did, holder.Did, subject, output), pipe));

            string jwt = (await File.ReadAllTextAsync(output)).TrimEnd('\r', '\n');
            Assert.DoesNotContain(Convert.ToHexString(issuer.Seed), jwt, StringComparison.Ordinal);
            Assert.True(Vcdm20JoseCredential.TryVerify(
                jwt, issuer.Did, holder.Did, "RoleCredential", Vocabulary,
                DateTimeOffset.UtcNow, out JsonElement claims));
            Assert.Equal("member", claims.GetProperty("role").GetString());
            Assert.False(Vcdm20JoseCredential.TryVerify(
                jwt, holder.Did, holder.Did, "RoleCredential", Vocabulary,
                DateTimeOffset.UtcNow, out _));
            Assert.False(Vcdm20JoseCredential.TryVerify(
                jwt, issuer.Did, holder.Did, "DifferentCredential", Vocabulary,
                DateTimeOffset.UtcNow, out _));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(output));
            }

            string[] check =
            [
                "verify-vc2-issuer", "--jwt-file", output,
                "--trusted-issuer", issuer.Did, "--holder", holder.Did,
                "--credential-type", "RoleCredential",
                "--context", Vocabulary.AbsoluteUri
            ];
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!).InvokeAsync(check));
            check[^1] = "https://other.example/vocab/role";
            Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!).InvokeAsync(check));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void MismatchedSignerCannotCreateCredentialAndExistingOutputIsNeverOverwritten()
    {
        var issuer = Identity();
        var impostor = Identity();
        var holder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            File.WriteAllText(subject,
                JsonSerializer.Serialize(new { id = holder.Did, role = "member" }));
            string output = Path.Combine(directory, "issued.jwt");
            using (var wrongPipe = Pipe(impostor.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKey(
                    Request(issuer.Did, holder.Did, subject, output), wrongPipe));
            }
            Assert.False(File.Exists(output));

            File.WriteAllText(output, "existing confidential file");
            using (var correctPipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKey(
                    Request(issuer.Did, holder.Did, subject, output), correctPipe));
            }
            Assert.Equal("existing confidential file", File.ReadAllText(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void InvalidSubjectIdOrOversizeInputCannotCreateJwt()
    {
        var issuer = Identity();
        var holder = Identity();
        var differentHolder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            string output = Path.Combine(directory, "issued.jwt");
            File.WriteAllText(subject,
                JsonSerializer.Serialize(new { id = differentHolder.Did, role = "member" }));
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKey(
                    Request(issuer.Did, holder.Did, subject, output), pipe));
            }
            Assert.False(File.Exists(output));

            File.WriteAllText(subject, JsonSerializer.Serialize(new
            {
                id = holder.Did,
                role = new string('x', 17_000)
            }));
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKey(
                    Request(issuer.Did, holder.Did, subject, output), pipe));
            }
            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc2DidKeyIssueParameters Request(
        string issuer, string holder, string subject, string output)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new(issuer, holder, "RoleCredential", Vocabulary.AbsoluteUri,
            subject, now.AddMinutes(-1).ToString("O"),
            now.AddMinutes(10).ToString("O"), output);
    }

    private static MemoryStream Pipe(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string TemporaryDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-didkey-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
