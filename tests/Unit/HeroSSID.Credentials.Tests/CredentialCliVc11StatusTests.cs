using System.CommandLine;
using System.Globalization;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A non-SDK operator publishes a bounded original-issuer signed VC1.1
/// revocation observation; an independent verifier rejects revoked, tampered,
/// stale or wrong-signer evidence without treating absence as live status.
/// </summary>
public sealed class CredentialCliVc11StatusTests
{
    private const string IssuerName = "Example Membership Issuer";
    private const string CredentialId = "https://issuer.example/credentials/42";
    private const string Context = "https://issuer.example/vocab/member";
    private const string Type = "MembershipCredential";

    [Fact]
    public void AuthenticCleanStatusAcceptsPinnedOriginalAndRejectsAnotherIssuer()
    {
        var issuer = Identity();
        var foreign = Identity();
        var holder = Identity();
        string directory = DirectoryForTest();
        try
        {
            string credential = Issue(directory, issuer, holder.Did);
            string manifest = Manifest(directory, "clean.json", []);
            string snapshot = Path.Combine(directory, "clean.status.jwt");
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(issuer.Did, manifest, snapshot), SeedInput(issuer.Seed),
                TimeProvider.System));

            var pins = VerifyParameters(credential, snapshot, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins, DateTimeOffset.UtcNow));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins with { Pins = pins.Pins with { IssuerName = "Attacker" } },
                DateTimeOffset.UtcNow));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins with { Pins = pins.Pins with {
                    CredentialId = "https://issuer.example/credentials/other"
                } }, DateTimeOffset.UtcNow));

            string foreignSnapshot = Path.Combine(directory, "foreign.status.jwt");
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(foreign.Did, manifest, foreignSnapshot),
                SeedInput(foreign.Seed), TimeProvider.System));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins with { SnapshotFile = foreignSnapshot }, DateTimeOffset.UtcNow));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void RevocationTamperingAndInsufficientObservationFailClosed()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = DirectoryForTest();
        try
        {
            string credential = Issue(directory, issuer, holder.Did);
            string revokedManifest = Manifest(directory, "revoked.json",
                [File.ReadAllText(credential).TrimEnd('\r', '\n')]);
            string revokedSnapshot = Path.Combine(directory, "revoked.status.jwt");
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(issuer.Did, revokedManifest, revokedSnapshot),
                SeedInput(issuer.Seed), TimeProvider.System));
            var revokedPins = VerifyParameters(credential, revokedSnapshot,
                issuer.Did, holder.Did);
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                revokedPins, DateTimeOffset.UtcNow));

            string clean = Manifest(directory, "clean.json", []);
            string cleanSnapshot = Path.Combine(directory, "clean.status.jwt");
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(issuer.Did, clean, cleanSnapshot),
                SeedInput(issuer.Seed), TimeProvider.System));
            var pins = VerifyParameters(credential, cleanSnapshot, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins, DateTimeOffset.UtcNow));

            string[] segments = File.ReadAllText(cleanSnapshot).Trim().Split('.');
            Assert.Equal(3, segments.Length);
            segments[2] = (segments[2][0] == 'A' ? "B" : "A") + segments[2][1..];
            string tampered = Path.Combine(directory, "tampered.status.jwt");
            File.WriteAllText(tampered, string.Join(".", segments));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins with { SnapshotFile = tampered }, DateTimeOffset.UtcNow));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedStatus(
                pins with { MinimumObservedAt = DateTimeOffset.UtcNow
                    .AddSeconds(1).ToString("O", CultureInfo.InvariantCulture) },
                DateTimeOffset.UtcNow));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void WrongSeedAndPreexistingOutputNeverPublishAStatus()
    {
        var issuer = Identity();
        var foreign = Identity();
        string directory = DirectoryForTest();
        try
        {
            string clean = Manifest(directory, "clean.json", []);
            string output = Path.Combine(directory, "status.jwt");
            var parameters = IssueParameters(issuer.Did, clean, output);
            Assert.False(CredentialCommands.TryIssueVc11DidKeyStatus(
                parameters, SeedInput(foreign.Seed), TimeProvider.System));
            Assert.False(File.Exists(output));
            File.WriteAllText(output, "EXISTING_NO_OVERWRITE");
            Assert.False(CredentialCommands.TryIssueVc11DidKeyStatus(
                parameters, SeedInput(issuer.Seed), TimeProvider.System));
            Assert.Equal("EXISTING_NO_OVERWRITE", File.ReadAllText(output));

            string malformed = Path.Combine(directory, "malformed.json");
            File.WriteAllText(malformed, "{\"revoked\":[]}");
            Assert.False(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(issuer.Did, malformed,
                    Path.Combine(directory, "malformed.status.jwt")),
                SeedInput(issuer.Seed), TimeProvider.System));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task VerifierCliChecksGenuineSnapshotWithoutAnSdkCaller()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = DirectoryForTest();
        try
        {
            string credential = Issue(directory, issuer, holder.Did);
            string clean = Manifest(directory, "cli-clean.json", []);
            string snapshot = Path.Combine(directory, "cli.status.jwt");
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                IssueParameters(issuer.Did, clean, snapshot),
                SeedInput(issuer.Seed), TimeProvider.System));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(snapshot));
            }

            string[] arguments =
            [
                "verify-vc11-didkey-pinned-status",
                "--jwt-file", credential, "--snapshot-file", snapshot,
                "--trusted-issuer", issuer.Did, "--issuer-name", IssuerName,
                "--credential-id", CredentialId, "--holder", holder.Did,
                "--credential-type", Type, "--context", Context,
                "--minimum-observed-at",
                DateTimeOffset.UtcNow.AddSeconds(-10)
                    .ToString("O", CultureInfo.InvariantCulture)
            ];
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(arguments).ConfigureAwait(true));
            string[] wrongIssuer = (string[])arguments.Clone();
            wrongIssuer[Array.IndexOf(wrongIssuer, "--trusted-issuer") + 1] =
                Identity().Did;
            Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
                .InvokeAsync(wrongIssuer).ConfigureAwait(true));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc11StatusIssueParameters IssueParameters(
        string issuerDid, string manifest, string output) =>
        new(issuerDid, manifest, output,
            DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O",
                CultureInfo.InvariantCulture));

    private static CredentialCommands.Vc11StatusVerifyParameters VerifyParameters(
        string credential, string snapshot, string issuer, string holder) =>
        new(new CredentialCommands.Vc11PinnedVerifyParameters(
            credential, issuer, IssuerName, CredentialId, holder, Type, Context),
            snapshot, DateTimeOffset.UtcNow.AddSeconds(-10).ToString("O",
                CultureInfo.InvariantCulture));

    private static string Issue(
        string directory, (byte[] Seed, string Did) issuer, string holderDid)
    {
        string subjectPath = Path.Combine(directory, "subject.json");
        string output = Path.Combine(directory, "credential.jwt");
        File.WriteAllText(subjectPath,
            JsonSerializer.Serialize(new { id = holderDid, membership = "active" }));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Assert.True(CredentialCommands.TryIssueVc11DidKey(
            new CredentialCommands.Vc11IssueParameters(
                issuer.Did, IssuerName, CredentialId, holderDid, Type,
                Context, subjectPath, now.AddMinutes(-1).ToString("O",
                    CultureInfo.InvariantCulture),
                now.AddMinutes(8).ToString("O", CultureInfo.InvariantCulture),
                output), SeedInput(issuer.Seed)));
        return output;
    }

    private static string Manifest(string directory, string name, string[] revoked)
    {
        string path = Path.Combine(directory, name);
        File.WriteAllText(path, JsonSerializer.Serialize(revoked));
        return path;
    }

    private static MemoryStream SeedInput(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string DirectoryForTest()
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-vc11-status-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
