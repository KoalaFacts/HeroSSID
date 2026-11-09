using System.CommandLine;
using System.Text;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Issue real Ed25519 VC2 agent assertions from an issuer-owned seed pipe,
/// then verify them independently through the public CLI command.
/// </summary>
public sealed class CredentialCliVc2AgentScopeIssueTests
{
    private const string Context = "https://issuer.example/vocab/agent-scope/v1";
    private const string CredentialId = "https://issuer.example/credentials/agent/42";
    private const string Audience = "https://verifier.example/agent-requests";
    private const string Resource = "https://api.example/projects/42";
    private const string Action = "invoices.read";

    [Fact]
    public async Task RealIssuerSeedCreatesOriginalJwtAcceptedByIndependentCliVerifier()
    {
        var issuer = Identity();
        var agent = Identity();
        string folder = Folder();
        try
        {
            string output = Path.Combine(folder, "scope.jwt");
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.True(CredentialCommands.TryIssueVc2AgentScope(
                    Request(issuer.Did, agent.Did, output), pipe));
            }

            string jwt = (await File.ReadAllTextAsync(output).ConfigureAwait(true)).TrimEnd('\r', '\n');
            Assert.True(Vcdm20AgentScopeAssertion.TryVerify(
                jwt, issuer.Did, agent.Did, new Uri(Context),
                new Uri(CredentialId), new Uri(Audience), new Uri(Resource),
                Action, DateTimeOffset.UtcNow, out var verified));
            Assert.Equal(Action, verified.GetProperty("action").GetString());
            Assert.Equal(0, await CredentialCommands.CreateCommand(null!).InvokeAsync(
            [
                "verify-vc2-agent-scope", "--jwt-file", output,
                "--trusted-issuer", issuer.Did, "--agent", agent.Did,
                "--context", Context, "--credential-id", CredentialId,
                "--audience", Audience, "--resource", Resource,
                "--action", Action
            ]).ConfigureAwait(true));
            Assert.DoesNotContain(Convert.ToHexString(issuer.Seed), jwt,
                StringComparison.Ordinal);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(output));
            }
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void ForeignSeedCannotIssueForPinnedIssuerOrLeaveOutput()
    {
        var issuer = Identity();
        var agent = Identity();
        var attacker = Identity();
        string folder = Folder();
        try
        {
            string output = Path.Combine(folder, "scope.jwt");
            using var pipe = Pipe(attacker.Seed);
            Assert.False(CredentialCommands.TryIssueVc2AgentScope(
                Request(issuer.Did, agent.Did, output), pipe));
            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void WildcardActionOrLongLivedScopeIsRejectedWithoutArtifact()
    {
        var issuer = Identity();
        var agent = Identity();
        string folder = Folder();
        try
        {
            string output = Path.Combine(folder, "scope.jwt");
            var request = Request(issuer.Did, agent.Did, output);
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2AgentScope(
                    request with { Action = "*" }, pipe));
            }

            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2AgentScope(
                    request with
                    {
                        ValidUntil = DateTimeOffset.UtcNow.AddHours(2).ToString("O")
                    }, pipe));
            }

            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void ExistingOutputNeverOverwrittenAndInvalidResourceNeverSigned()
    {
        var issuer = Identity();
        var agent = Identity();
        string folder = Folder();
        try
        {
            string output = Path.Combine(folder, "scope.jwt");
            File.WriteAllText(output, "retain this artifact");
            var request = Request(issuer.Did, agent.Did, output);
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2AgentScope(request, pipe));
            }

            Assert.Equal("retain this artifact", File.ReadAllText(output));
            File.Delete(output);
            using (var pipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2AgentScope(
                    request with { Resource = "https://api.example/projects/42?admin=true" },
                    pipe));
            }

            Assert.False(File.Exists(output));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    private static CredentialCommands.Vc2AgentScopeIssueParameters Request(
        string issuer, string agent, string output)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new(issuer, agent, Context, CredentialId, Audience, Resource,
            Action, now.AddSeconds(-5).ToString("O"),
            now.AddMinutes(5).ToString("O"), output);
    }

    private static MemoryStream Pipe(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string Folder()
    {
        string path = Path.Combine(Path.GetTempPath(),
            "herossid-agent-scope-issue-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static (byte[] Seed, string Did) Identity()
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
}
