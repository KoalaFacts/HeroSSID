using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Genuine issuer seed and externally pinned did:key + VC1.1 JWT policy;
/// passing an issuer signature never establishes holder or business authority.
/// </summary>
public sealed class CredentialCliVc11IssuerTests
{
    private const string IssuerName = "Example Membership Issuer";
    private static readonly Uri Context = new("https://issuer.example/vocab/membership");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member-123");

    [Fact]
    public void OriginalVc11JwtIsSignedAndIndependentlyVerifiable()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = NewDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string subjectFile = Path.Combine(directory, "subject.json");
            string output = Path.Combine(directory, "credential.jwt");
            File.WriteAllText(subjectFile, JsonSerializer.Serialize(
                new { id = holder.Did, membership = "active" }));
            var parameters = Request(issuer.Did, holder.Did, subjectFile, output, now);
            using var pipe = Pipe(issuer.Seed);

            Assert.True(CredentialCommands.TryIssueVc11DidKey(parameters, pipe));
            string jwt = File.ReadAllText(output).TrimEnd('\r', '\n');
            Assert.True(JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
                jwt, issuer.Did, IssuerName, holder.Did, "MembershipCredential",
                Context, CredentialId, DateTimeOffset.UtcNow, out JsonElement signedSubject));
            Assert.Equal("active", signedSubject.GetProperty("membership").GetString());
            Assert.DoesNotContain(Convert.ToHexString(issuer.Seed), jwt, StringComparison.Ordinal);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(output));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ForeignSeedAndWrongHolderFailClosedWithoutOutput()
    {
        var issuer = Identity();
        var attacker = Identity();
        var holder = Identity();
        string directory = NewDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string subjectFile = Path.Combine(directory, "subject.json");
            string output = Path.Combine(directory, "credential.jwt");
            File.WriteAllText(subjectFile, JsonSerializer.Serialize(
                new { id = holder.Did, membership = "active" }));
            var request = Request(issuer.Did, holder.Did, subjectFile, output, now);
            using (var foreignPipe = Pipe(attacker.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc11DidKey(request, foreignPipe));
            }

            Assert.False(File.Exists(output));
            using (var authenticPipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc11DidKey(
                    request with { HolderDid = attacker.Did }, authenticPipe));
            }

            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void DuplicateSubjectPropertiesAndExistingOutputFailClosed()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = NewDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string subjectFile = Path.Combine(directory, "subject.json");
            string output = Path.Combine(directory, "credential.jwt");
            File.WriteAllText(subjectFile,
                "{\"id\":\"" + holder.Did + "\",\"membership\":\"active\",\"membership\":\"forged\"}");
            var request = Request(issuer.Did, holder.Did, subjectFile, output, now);
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc11DidKey(request, pipe));
            }

            Assert.False(File.Exists(output));
            File.WriteAllText(subjectFile, JsonSerializer.Serialize(
                new { id = holder.Did, membership = "active" }));
            File.WriteAllText(output, "do not overwrite");
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc11DidKey(request, pipe));
            }

            Assert.Equal("do not overwrite", File.ReadAllText(output));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc11IssueParameters Request(
        string issuer, string holder, string subjectFile, string output, DateTimeOffset now) =>
        new(issuer, IssuerName, CredentialId.AbsoluteUri, holder,
            "MembershipCredential", Context.AbsoluteUri, subjectFile,
            now.AddSeconds(-3).ToString("O"), now.AddMinutes(8).ToString("O"), output);

    private static MemoryStream Pipe(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string NewDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-vc11-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
