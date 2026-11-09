using System.Security.Cryptography;
using System.Text;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Genuine issuer, agent-holder and verifier use distinct Ed25519 keys.
/// The CLI must not promote a signed scope into business authorization.
/// </summary>
public sealed class CredentialCliVc2AgentScopeVerifierStatusTests
{
    [Fact]
    public void VerifierCreatesARealPolicyBoundOneUseAgentRequest()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.Request());
        string signed = File.ReadAllText(scenario.RequestFile).TrimEnd('\r', '\n');
        Assert.True(OfflineSignedPresentationRequest.TryReadPolicyBound(
            signed, scenario.Verifier.Did, Scenario.Audience,
            Vcdm20AgentScopeAssertion.CredentialType, Scenario.Context,
            TimeProvider.System, out var challenge));
        Assert.NotNull(challenge);
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            signed, scenario.Verifier.Did, Scenario.Audience,
            TimeProvider.System, out _));
        Assert.True(File.Exists(scenario.SessionFile));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(scenario.SessionFile));
        }
    }

    [Fact]
    public void RealIssuerAndAgentAndVerifierAndCurrentStatusAreAcceptedExactlyOnce()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.Request());
        scenario.Present();
        scenario.Status();
        Assert.True(scenario.Verify());
        Assert.False(scenario.Verify());
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public void RealHolderProofWithWrongScopeSpendsNonceButNeverAuthorizes()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.Request());
        scenario.Present();
        scenario.Status();
        Assert.False(scenario.Verify(action: "invoices.write"));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
        Assert.False(scenario.Verify());
    }

    [Fact]
    public void IssuerRevocationDeniesAndSpendsTheGenuineAgentProof()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.Request());
        scenario.Present();
        scenario.Status(revoked: true);
        Assert.False(scenario.Verify());
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
        scenario.Status();
        Assert.False(scenario.Verify());
    }

    [Fact]
    public void ForgedHolderSignatureOrForeignVerifierPinCannotSpendLegitimateNonce()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.Request());
        scenario.Present();
        scenario.Status();

        string original = File.ReadAllText(scenario.VpFile).TrimEnd('\r', '\n');
        string[] parts = original.Split('.');
        parts[2] = (parts[2][0] == 'A' ? "B" : "A") + parts[2][1..];
        File.WriteAllText(scenario.VpFile, string.Join('.', parts));
        Assert.False(scenario.Verify());
        Assert.True(File.Exists(scenario.SessionFile));

        File.WriteAllText(scenario.VpFile, original);
        Assert.False(scenario.Verify(verifierDid: Scenario.Identity().Did));
        Assert.True(File.Exists(scenario.SessionFile));
        Assert.True(scenario.Verify());
    }

    private sealed class Scenario : IDisposable
    {
        internal const string Audience = "https://verifier.example/agent-requests";
        internal static readonly Uri Context = new("https://issuer.example/vocab/agent-scope/v1");
        private const string Action = "invoices.read";
        private static readonly Uri CredentialId =
            new("https://issuer.example/credentials/agent/42");
        private static readonly Uri Resource = new("https://api.example/projects/42");

        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Agent = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        private readonly Guid _tenant = Guid.NewGuid();
        private readonly string _folder = Path.Combine(Path.GetTempPath(),
            "herossid-agent-proof-cli-" + Guid.NewGuid().ToString("N"));
        internal readonly string RequestFile;
        internal readonly string SessionFile;
        internal readonly string VpFile;
        private readonly string _snapshotFile;
        private string _original = string.Empty;

        internal Scenario()
        {
            Directory.CreateDirectory(_folder);
            RequestFile = Path.Combine(_folder, "request.jwt");
            SessionFile = Path.Combine(_folder, "challenge.json");
            VpFile = Path.Combine(_folder, "agent-vp.jwt");
            _snapshotFile = Path.Combine(_folder, "issuer-status.jwt");
        }

        internal bool Request()
        {
            using var stream = SeedInput(Verifier.Seed);
            return CredentialCommands.TryCreateVc2AgentScopeVerifierRequest(
                new(Verifier.Did, _tenant.ToString("D"), Audience,
                    Issuer.Did, Context.AbsoluteUri, RequestFile, SessionFile, 120),
                stream);
        }

        internal void Present()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            _original = Vcdm20AgentScopeAssertion.Create(
                Issuer.Did, Agent.Did, Context, CredentialId,
                new Uri(Audience), Resource, Action, Issuer.Seed,
                now.AddSeconds(-5), now.AddMinutes(5));
            string request = File.ReadAllText(RequestFile).TrimEnd('\r', '\n');
            string vp = Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
                request, Verifier.Did, Audience, _original,
                Vcdm20AgentScopeAssertion.CredentialType, Context,
                CredentialId, new Uri(Audience), Agent.Did, Agent.Seed,
                TimeProvider.System);
            File.WriteAllText(VpFile, vp);
        }

        internal void Status(bool revoked = false)
        {
            var observed = DateTimeOffset.FromUnixTimeSeconds(
                DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            string snapshot = Vcdm20RevocationSnapshot.Create(
                Issuer.Did, revoked ? [_original] : [],
                Issuer.Seed, observed, TimeProvider.System);
            File.WriteAllText(_snapshotFile, snapshot);
        }

        internal bool Verify(string? action = null, string? verifierDid = null) =>
            CredentialCommands.TryVerifyVc2AgentScopePresentationWithStatus(
                new(verifierDid ?? Verifier.Did, _tenant.ToString("D"),
                    Audience, Issuer.Did,
                    Vcdm20AgentScopeAssertion.CredentialType, Context.AbsoluteUri,
                    RequestFile, SessionFile, VpFile),
                Agent.Did, CredentialId.AbsoluteUri, Resource.AbsoluteUri,
                action ?? Action, _snapshotFile,
                DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O"));

        internal static MemoryStream SeedInput(byte[] seed) =>
            new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

        internal static (byte[] Seed, string Did) Identity()
        {
            using Key key = Key.Create(SignatureAlgorithm.Ed25519,
                new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var prefixed = new byte[34];
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
            Directory.Delete(_folder, recursive: true);
        }
    }
}
