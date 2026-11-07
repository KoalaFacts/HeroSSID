using System.CommandLine;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20DidWebIssuerCliIssuanceTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Issuer";
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/active-42");
    private static readonly Uri Audience = new("https://verifier.example/entry");
    private static readonly Uri Context = new("https://issuer.example/vocab/member");

    [Fact]
    public async Task PipeSeedIssuesAuthenticVc2WithIndependentVerifierAndNeverEchoesSeed()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            File.WriteAllText(subject, JsonSerializer.Serialize(new { id = holder.Did, membership = "active" }));
            string output = Path.Combine(directory, "signed.jwt");
            var request = Request(issuer.PublicKey, holder.Did, subject, output);
            using var pipe = Pipe(issuer.Seed);

            Assert.True(CredentialCommands.TryIssueVc2DidWeb(request, pipe));
            string jwt = File.ReadAllText(output).TrimEnd('\r', '\n');
            Assert.DoesNotContain(Convert.ToHexString(issuer.Seed), jwt, StringComparison.Ordinal);
            Assert.True(Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
                jwt, IssuerDid, IssuerDid + "#key-1", issuer.PublicKey, IssuerName,
                CredentialId, Audience, holder.Did, "MembershipCredential", Context,
                DateTimeOffset.UtcNow, out JsonElement claims));
            Assert.Equal("active", claims.GetProperty("membership").GetString());
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(output));
            }

            // This is a real command-to-command roundtrip: issuance never
            // adds trust to the verifier, which still pins the original key.
            string[] verification =
            [
                "verify-vc2-didweb-recipient-claim", "--jwt-file", output,
                "--trusted-issuer", IssuerDid,
                "--verification-method", IssuerDid + "#key-1",
                "--public-key-hex", Convert.ToHexString(issuer.PublicKey),
                "--issuer-name", IssuerName,
                "--credential-id", CredentialId.AbsoluteUri,
                "--audience", Audience.AbsoluteUri,
                "--holder", holder.Did,
                "--credential-type", "MembershipCredential",
                "--context", Context.AbsoluteUri,
                "--claim-name", "membership",
                "--claim-value", "active"
            ];
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(verification).ConfigureAwait(true));
            verification[^1] = "expired";
            Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(verification).ConfigureAwait(true));
            Assert.False(Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
                jwt, IssuerDid, IssuerDid + "#key-1", issuer.PublicKey, IssuerName,
                CredentialId, new Uri("https://different.example/entry"), holder.Did,
                "MembershipCredential", Context, DateTimeOffset.UtcNow, out _));
            Assert.NotEqual("{}", File.ReadAllText(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void InvalidOrMismatchedKeyCannotProduceOrOverwriteCredential()
    {
        var issuer = Identity();
        var wrong = Identity();
        var holder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            File.WriteAllText(subject, JsonSerializer.Serialize(new { id = holder.Did, membership = "active" }));
            string output = Path.Combine(directory, "signed.jwt");
            using (var pipe = Pipe(wrong.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidWeb(
                    Request(issuer.PublicKey, holder.Did, subject, output), pipe));
            }

            Assert.False(File.Exists(output));
            File.WriteAllText(output, "do not replace");
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidWeb(
                    Request(issuer.PublicKey, holder.Did, subject, output), pipe));
            }

            Assert.Equal("do not replace", File.ReadAllText(output));
            string otherOutput = Path.Combine(directory, "other.jwt");
            using var bad = new MemoryStream(Encoding.ASCII.GetBytes("invalid\\n"));
            Assert.False(CredentialCommands.TryIssueVc2DidWeb(
                Request(issuer.PublicKey, holder.Did, subject, otherOutput), bad));
            Assert.False(File.Exists(otherOutput));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void RejectsDuplicateSubjectClaimBeforeReleasingArtifact()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = TemporaryDirectory();
        try
        {
            string subject = Path.Combine(directory, "subject.json");
            File.WriteAllText(subject, "{\"id\":\"" + holder.Did +
                "\",\"membership\":\"active\",\"membership\":\"expired\"}");
            string output = Path.Combine(directory, "signed.jwt");
            using var pipe = Pipe(issuer.Seed);
            Assert.False(CredentialCommands.TryIssueVc2DidWeb(
                Request(issuer.PublicKey, holder.Did, subject, output), pipe));
            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc2DidWebIssueParameters Request(
        byte[] publicKey, string holderDid, string subjectPath, string outputPath)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new(IssuerDid, IssuerDid + "#key-1", Convert.ToHexString(publicKey),
            IssuerName, CredentialId.AbsoluteUri, Audience.AbsoluteUri,
            holderDid, "MembershipCredential", Context.AbsoluteUri,
            subjectPath, now.AddMinutes(-1).ToString("O"),
            now.AddMinutes(10).ToString("O"), outputPath);
    }

    private static MemoryStream Pipe(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string TemporaryDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-issuer-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
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
