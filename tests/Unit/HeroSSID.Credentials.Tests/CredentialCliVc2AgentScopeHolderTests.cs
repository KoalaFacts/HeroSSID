using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Test-first independent non-SDK Agent holder flow. The verifier signs the
/// request, the issuer signs the scope, and the Agent alone signs the VP.
/// A successful signature is never the receiving service's authorization.
/// </summary>
public sealed class CredentialCliVc2AgentScopeHolderTests
{
    [Fact]
    public void GenuineSeparateIssuerVerifierAndAgentSignaturesCompleteTheOneUseCliFlow()
    {
        using var scenario = new Scenario();
        using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
        {
            Assert.True(CredentialCommands.TryPresentVc2AgentScope(scenario.Policy(), seed));
        }

        string presentation = File.ReadAllText(scenario.OutputFile).TrimEnd('\r', '\n');
        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        Assert.Equal(scenario.Agent.Did, payload.RootElement.GetProperty("holder").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(scenario.RequestJwt))),
            payload.RootElement.GetProperty("herossidRequestSha256").GetString());
        Assert.Equal("EnvelopedVerifiableCredential",
            payload.RootElement.GetProperty("verifiableCredential")[0]
                .GetProperty("type")[0].GetString());
        Assert.True(scenario.Verify());
        Assert.False(scenario.Verify());
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(scenario.OutputFile));
        }
    }

    [Fact]
    public void ForeignAgentSeedAndUntrustedVerifierOrIssuerFailWithoutPresentation()
    {
        using var scenario = new Scenario();
        var foreign = Scenario.Identity();
        try
        {
            using (var seed = Scenario.SeedInput(foreign.Seed))
            {
                Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                    scenario.Policy(), seed));
            }

            using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
            {
                Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                    scenario.Policy() with { TrustedVerifierDid = foreign.Did }, seed));
            }

            using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
            {
                Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                    scenario.Policy() with { TrustedIssuerDid = foreign.Did }, seed));
            }

            using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
            {
                Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                    scenario.Policy() with { AgentDid = foreign.Did }, seed));
            }

            Assert.False(File.Exists(scenario.OutputFile));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(foreign.Seed);
        }
    }

    [Fact]
    public void WrongAgentActionResourceOrSignedCredentialIdCannotBeDisclosed()
    {
        using var scenario = new Scenario();
        var policy = scenario.Policy();
        var wrong = new[]
        {
            policy with { Action = "invoices.write" },
            policy with { Resource = "https://api.example/projects/other" },
            policy with { CredentialId = "https://issuer.example/credentials/other" },
            policy with { Audience = "https://verifier.example/other" },
            policy with { Context = "https://issuer.example/vocab/other" }
        };
        foreach (var request in wrong)
        {
            using var seed = Scenario.SeedInput(scenario.Agent.Seed);
            Assert.False(CredentialCommands.TryPresentVc2AgentScope(request, seed));
        }

        Assert.False(File.Exists(scenario.OutputFile));
    }

    [Fact]
    public void ForgedVerifierRequestOrIssuerJwtCannotProduceHolderProof()
    {
        using var scenario = new Scenario();
        string forgedRequest = Path.Combine(scenario.DirectoryPath, "forged-request.jwt");
        string forgedCredential = Path.Combine(scenario.DirectoryPath, "forged-credential.jwt");
        File.WriteAllText(forgedRequest, TamperSignature(scenario.RequestJwt));
        File.WriteAllText(forgedCredential, TamperSignature(scenario.CredentialJwt));
        using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                scenario.Policy() with { RequestJwtFile = forgedRequest }, seed));
        }

        using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                scenario.Policy() with { CredentialJwtFile = forgedCredential }, seed));
        }

        Assert.False(File.Exists(scenario.OutputFile));
    }

    [Fact]
    public void DisclosureAcknowledgementAndCreateNewPrivateOutputAreRequired()
    {
        using var scenario = new Scenario();
        using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                scenario.Policy() with { FullDisclosureAcknowledged = false }, seed));
        }

        Assert.False(File.Exists(scenario.OutputFile));
        File.WriteAllText(scenario.OutputFile, "pre-existing data");
        using (var seed = Scenario.SeedInput(scenario.Agent.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2AgentScope(
                scenario.Policy(), seed));
        }

        Assert.Equal("pre-existing data", File.ReadAllText(scenario.OutputFile));
    }

    private static string TamperSignature(string jwt)
    {
        string[] segments = jwt.Split('.');
        Assert.Equal(3, segments.Length);
        segments[2] = (segments[2][0] == 'A' ? "B" : "A") + segments[2][1..];
        return string.Join('.', segments);
    }

    private sealed class Scenario : IDisposable
    {
        internal const string Audience = "https://verifier.example/agent-requests";
        internal const string Context = "https://issuer.example/vocab/agent-scope/v1";
        internal const string CredentialId = "https://issuer.example/credentials/agent/42";
        internal const string Resource = "https://api.example/projects/42";
        internal const string Action = "invoices.read";

        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Agent = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(),
            "herossid-agent-holder-cli-" + Guid.NewGuid().ToString("N"));
        internal readonly string RequestFile;
        internal readonly string CredentialFile;
        internal readonly string SnapshotFile;
        internal readonly string SessionFile;
        internal readonly string OutputFile;
        internal readonly string RequestJwt;
        internal readonly string CredentialJwt;
        private readonly string _tenant = Guid.NewGuid().ToString("D");

        internal Scenario()
        {
            Directory.CreateDirectory(DirectoryPath);
            RequestFile = Path.Combine(DirectoryPath, "request.jwt");
            CredentialFile = Path.Combine(DirectoryPath, "credential.jwt");
            SnapshotFile = Path.Combine(DirectoryPath, "status.jwt");
            SessionFile = Path.Combine(DirectoryPath, "session.json");
            OutputFile = Path.Combine(DirectoryPath, "agent-vp.jwt");

            using (var verifierSeed = SeedInput(Verifier.Seed))
            {
                Assert.True(CredentialCommands.TryCreateVc2AgentScopeVerifierRequest(
                    new(Verifier.Did, _tenant, Audience, Issuer.Did,
                        Context, RequestFile, SessionFile, 120), verifierSeed));
            }

            RequestJwt = File.ReadAllText(RequestFile).TrimEnd('\r', '\n');
            DateTimeOffset now = DateTimeOffset.UtcNow;
            CredentialJwt = Vcdm20AgentScopeAssertion.Create(
                Issuer.Did, Agent.Did, new Uri(Context), new Uri(CredentialId),
                new Uri(Audience), new Uri(Resource), Action, Issuer.Seed,
                now.AddSeconds(-5), now.AddMinutes(5));
            File.WriteAllText(CredentialFile, CredentialJwt);
            string status = Vcdm20RevocationSnapshot.Create(
                Issuer.Did, [], Issuer.Seed, DateTimeOffset.FromUnixTimeSeconds(
                    now.ToUnixTimeSeconds()), TimeProvider.System);
            File.WriteAllText(SnapshotFile, status);
        }

        internal CredentialCommands.Vc2AgentScopeHolderParameters Policy() =>
            new(RequestFile, CredentialFile, Verifier.Did, Audience,
                Issuer.Did, Agent.Did, Context, CredentialId,
                Resource, Action, OutputFile, true);

        internal bool Verify() => CredentialCommands.TryVerifyVc2AgentScopePresentationWithStatus(
            new(Verifier.Did, _tenant, Audience, Issuer.Did,
                Vcdm20AgentScopeAssertion.CredentialType, Context,
                RequestFile, SessionFile, OutputFile),
            Agent.Did, CredentialId, Resource, Action, SnapshotFile,
            DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O"));

        internal static MemoryStream SeedInput(byte[] seed) =>
            new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

        internal static (byte[] Seed, string Did) Identity()
        {
            using Key key = Key.Create(SignatureAlgorithm.Ed25519,
                new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            byte[] prefixed = new byte[34];
            prefixed[0] = 0xed;
            prefixed[1] = 0x01;
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
            return (key.Export(KeyBlobFormat.RawPrivateKey),
                "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Issuer.Seed);
            CryptographicOperations.ZeroMemory(Agent.Seed);
            CryptographicOperations.ZeroMemory(Verifier.Seed);
            Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
