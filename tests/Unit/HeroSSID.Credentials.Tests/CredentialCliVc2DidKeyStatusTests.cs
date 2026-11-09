using System.Security.Cryptography;
using System.Text;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A no-SDK operator must be able to sign a genuine short-lived VC2 status
/// for agent credentials; signatures do not imply a live or complete registry.
/// </summary>
public sealed class CredentialCliVc2DidKeyStatusTests
{
    private const string Context = "https://issuer.example/vocab/agent-scope/v1";
    private const string CredentialId = "https://issuer.example/credentials/agent/42";
    private const string Audience = "https://verifier.example/agent-requests";
    private const string Resource = "https://api.example/projects/42";

    [Fact]
    public void EmptyAuthoritativeSetCreatesSignedNotListedStatusWithPrivateOutput()
    {
        using var fixture = new Fixture();
        File.WriteAllText(fixture.ManifestFile, "");
        using (var seed = fixture.SeedInput())
        {
            Assert.True(CredentialCommands.TryIssueVc2DidKeyStatus(
                fixture.Parameters(), seed));
        }

        string snapshot = File.ReadAllText(fixture.OutputFile).TrimEnd('\r', '\n');
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                snapshot, fixture.CredentialJwt, fixture.IssuerDid,
                DateTimeOffset.UtcNow,
                fixture.ObservedAt.AddSeconds(-1)));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(fixture.OutputFile));
        }
    }

    [Fact]
    public void OriginalRevokedAgentJwtAppearsAsAuthenticRevokedWithoutJwtRewriting()
    {
        using var fixture = new Fixture();
        File.WriteAllText(fixture.ManifestFile, fixture.CredentialJwt + "\n");
        using (var seed = fixture.SeedInput())
        {
            Assert.True(CredentialCommands.TryIssueVc2DidKeyStatus(
                fixture.Parameters(), seed));
        }

        string snapshot = File.ReadAllText(fixture.OutputFile).TrimEnd('\r', '\n');
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(
                snapshot, fixture.CredentialJwt, fixture.IssuerDid,
                DateTimeOffset.UtcNow));
    }

    [Fact]
    public void WrongIssuerSeedCannotPublishStatusOrOverwriteExistingOutput()
    {
        using var fixture = new Fixture();
        File.WriteAllText(fixture.ManifestFile, "");
        var foreign = Fixture.NewIdentity();
        try
        {
            using (var seed = new MemoryStream(Encoding.ASCII.GetBytes(
                Convert.ToHexString(foreign.Seed) + "\n")))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKeyStatus(
                    fixture.Parameters(), seed));
            }

            Assert.False(File.Exists(fixture.OutputFile));
            File.WriteAllText(fixture.OutputFile, "existing status");
            using (var seed = fixture.SeedInput())
            {
                Assert.False(CredentialCommands.TryIssueVc2DidKeyStatus(
                    fixture.Parameters(), seed));
            }

            Assert.Equal("existing status", File.ReadAllText(fixture.OutputFile));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(foreign.Seed);
        }
    }

    [Fact]
    public void ForgedRevokedJwtAndStaleObservationCannotProduceStatus()
    {
        using var fixture = new Fixture();
        string[] pieces = fixture.CredentialJwt.Split('.');
        pieces[2] = (pieces[2][0] == 'A' ? "B" : "A") + pieces[2][1..];
        File.WriteAllText(fixture.ManifestFile, string.Join('.', pieces) + "\n");

        using (var seed = fixture.SeedInput())
        {
            Assert.False(CredentialCommands.TryIssueVc2DidKeyStatus(
                fixture.Parameters(), seed));
        }

        File.WriteAllText(fixture.ManifestFile, "");
        using (var seed = fixture.SeedInput())
        {
            Assert.False(CredentialCommands.TryIssueVc2DidKeyStatus(
                fixture.Parameters() with
                {
                    ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-3).ToString("O")
                }, seed));
        }

        Assert.False(File.Exists(fixture.OutputFile));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] _issuerSeed;
        private readonly byte[] _agentSeed;
        internal readonly string IssuerDid;
        internal readonly string AgentDid;
        internal readonly string Folder = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-didkey-status-" + Guid.NewGuid().ToString("N"));
        internal readonly string ManifestFile;
        internal readonly string OutputFile;
        internal readonly string CredentialJwt;
        internal readonly DateTimeOffset ObservedAt;

        internal Fixture()
        {
            Directory.CreateDirectory(Folder);
            ManifestFile = Path.Combine(Folder, "revoked.txt");
            OutputFile = Path.Combine(Folder, "snapshot.jwt");
            (_issuerSeed, IssuerDid) = NewIdentity();
            (_agentSeed, AgentDid) = NewIdentity();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ObservedAt = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
            CredentialJwt = Vcdm20AgentScopeAssertion.Create(
                IssuerDid, AgentDid, new Uri(Context), new Uri(CredentialId),
                new Uri(Audience), new Uri(Resource), "invoices.read",
                _issuerSeed, now.AddSeconds(-10), now.AddMinutes(5));
        }

        internal CredentialCommands.Vc2DidKeyStatusIssueParameters Parameters() =>
            new(IssuerDid, ManifestFile, ObservedAt.ToString("O"), OutputFile);

        internal MemoryStream SeedInput() =>
            new(Encoding.ASCII.GetBytes(Convert.ToHexString(_issuerSeed) + "\n"));

        internal static (byte[] Seed, string Did) NewIdentity()
        {
            using Key key = Key.Create(SignatureAlgorithm.Ed25519,
                new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                });
            byte[] prefixed = new byte[34];
            prefixed[0] = 0xed;
            prefixed[1] = 0x01;
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
            return (key.Export(KeyBlobFormat.RawPrivateKey),
                "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_issuerSeed);
            CryptographicOperations.ZeroMemory(_agentSeed);
            Directory.Delete(Folder, recursive: true);
        }
    }
}
