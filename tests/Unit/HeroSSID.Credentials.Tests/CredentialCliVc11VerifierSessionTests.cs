using System.CommandLine;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Offline verifier must own a durable one-use challenge, independently pin issuer,
/// verifier, audience and type, and accept a genuine separate holder signature once.
/// No identity vetting, status, consent proof or business authorization is implied.
/// </summary>
public sealed class CredentialCliVc11VerifierSessionTests
{
    [Fact]
    public void VerifierIssuesSignedRequestAndAcceptsRealHolderPresentationOnlyOnce()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        Assert.True(CredentialCommands.TryVerifyVc11VerifierPresentation(scenario.Check()));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(scenario.Check()));
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public void ForeignPolicyAndTamperedRequestOrPresentationCannotSpendVerifierChallenge()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        var foreign = Scenario.Identity();
        var check = scenario.Check();
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(
            check with { TrustedIssuerDid = foreign.Did }));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(
            check with { VerifierDid = foreign.Did }));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(
            check with { CredentialType = "OtherCredential" }));

        string originalRequest = File.ReadAllText(scenario.RequestFile);
        File.WriteAllText(scenario.RequestFile, Tamper(originalRequest.Trim()));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(check));
        File.WriteAllText(scenario.RequestFile, originalRequest);

        string originalVp = File.ReadAllText(scenario.VpFile);
        File.WriteAllText(scenario.VpFile, Tamper(originalVp.Trim()));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentation(check));
        File.WriteAllText(scenario.VpFile, originalVp);

        Assert.True(CredentialCommands.TryVerifyVc11VerifierPresentation(check));
    }

    [Fact]
    public async Task SimultaneousVerifiersConsumeTheSameLocalChallengeAtMostOnce()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        var policy = scenario.Check();
        Task<bool> first = Task.Run(() =>
            CredentialCommands.TryVerifyVc11VerifierPresentation(policy));
        Task<bool> second = Task.Run(() =>
            CredentialCommands.TryVerifyVc11VerifierPresentation(policy));
        bool[] accepted = await Task.WhenAll(first, second);
        Assert.Single(accepted, static success => success);
    }

    [Fact]
    public void VerifierNeverOverwritesOutputFilesAndRejectsUnboundedLifetime()
    {
        using var scenario = new Scenario();
        File.WriteAllText(scenario.RequestFile, "must-stay");
        Assert.False(scenario.IssueRequest());
        Assert.Equal("must-stay", File.ReadAllText(scenario.RequestFile));
        Assert.False(File.Exists(scenario.SessionFile));
        File.Delete(scenario.RequestFile);

        Assert.False(scenario.IssueRequest(lifetimeSeconds: 301));
        Assert.False(File.Exists(scenario.RequestFile));
        Assert.False(File.Exists(scenario.SessionFile));
    }


    [Fact]
    public void StatusAwareVerifierAcceptsOnlyOneGenuineIssuerAndHolderPresentation()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        string snapshot = scenario.IssueStatus();
        string cutoff = DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O");

        Assert.True(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            scenario.Check(), snapshot, cutoff));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            scenario.Check(), snapshot, cutoff));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public void AuthenticRevokedCredentialFailsAfterNonceConsumption()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        string revokedSnapshot = scenario.IssueStatus(revoked: true);

        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            scenario.Check(), revokedSnapshot,
            DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O")));
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public void ForeignStatusAndForgedHolderProofCannotProduceAStatusAwareSuccess()
    {
        using var foreign = new Scenario();
        Assert.True(foreign.IssueRequest());
        Assert.True(foreign.Present());
        string foreignSnapshot = foreign.IssueStatus(foreignIssuer: true);
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            foreign.Check(), foreignSnapshot,
            DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O")));

        using var forged = new Scenario();
        Assert.True(forged.IssueRequest());
        Assert.True(forged.Present());
        string snapshot = forged.IssueStatus();
        string original = File.ReadAllText(forged.VpFile);
        File.WriteAllText(forged.VpFile, Tamper(original.Trim()));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            forged.Check(), snapshot,
            DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O")));
        Assert.True(File.Exists(forged.SessionFile));
        File.WriteAllText(forged.VpFile, original);
        Assert.True(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            forged.Check(), snapshot,
            DateTimeOffset.UtcNow.AddSeconds(-15).ToString("O")));
    }

    [Fact]
    public void FutureCutoffCannotSpendButStaleIssuerObservationConsumesARealHolderChallenge()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        string snapshot = scenario.IssueStatus();

        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            scenario.Check(), snapshot,
            DateTimeOffset.UtcNow.AddMinutes(1).ToString("O")));
        Assert.True(File.Exists(scenario.SessionFile));
        Assert.False(CredentialCommands.TryVerifyVc11VerifierPresentationWithStatus(
            scenario.Check(), snapshot,
            DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O")));
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public async Task RegisteredOfflineStatusVerifierCommandAcceptsOneAuthenticSessionOnly()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        string snapshot = scenario.IssueStatus();
        string[] args =
        [
            "verify-vc11-didkey-vp-status",
            "--verifier-did", scenario.Verifier.Did,
            "--tenant-id", scenario.Tenant.ToString("D"),
            "--audience", scenario.Audience,
            "--trusted-issuer", scenario.Issuer.Did,
            "--credential-type", Scenario.CredentialType,
            "--context", Scenario.Context.AbsoluteUri,
            "--request-jwt-file", scenario.RequestFile,
            "--session-file", scenario.SessionFile,
            "--presentation-jwt-file", scenario.VpFile,
            "--snapshot-file", snapshot,
            "--minimum-observed-at", DateTimeOffset.UtcNow
                .AddSeconds(-15).ToString("O")
        ];
        string[] missingSnapshot = (string[])args.Clone();
        missingSnapshot[Array.IndexOf(missingSnapshot, "--snapshot-file") + 1] =
            Path.Combine(scenario.DirectoryPath, "absent.status.jwt");
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(missingSnapshot).ConfigureAwait(true));
        Assert.True(File.Exists(scenario.SessionFile));
        Assert.Equal(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(args).ConfigureAwait(true));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(args).ConfigureAwait(true));
    }

    private static string Tamper(string original)
    {
        string[] segments = original.Split('.');
        Assert.Equal(3, segments.Length);
        segments[1] = (segments[1][0] == 'A' ? "B" : "A") + segments[1][1..];
        return string.Join('.', segments);
    }

    private sealed class Scenario : IDisposable
    {
        internal const string CredentialType = "MembershipCredential";
        internal static readonly Uri Context = new("https://issuer.example/vocab/membership");
        private const string IssuerName = "Independently Approved Issuer";
        private const string CredentialId = "https://issuer.example/credentials/member-123";
        internal readonly string DirectoryPath = Path.Combine(
            Path.GetTempPath(), "herossid-verifier-session-" + Guid.NewGuid().ToString("N"));
        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Holder = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        internal readonly Guid Tenant = Guid.NewGuid();
        internal readonly string Audience;
        internal readonly string RequestFile;
        internal readonly string SessionFile;
        internal readonly string CredentialFile;
        internal readonly string VpFile;

        internal Scenario()
        {
            Directory.CreateDirectory(DirectoryPath);
            Audience = "decentralized_identifier:" + Verifier.Did;
            RequestFile = Path.Combine(DirectoryPath, "request.jwt");
            SessionFile = Path.Combine(DirectoryPath, "challenge.json");
            CredentialFile = Path.Combine(DirectoryPath, "issuer.jwt");
            VpFile = Path.Combine(DirectoryPath, "holder-vp.jwt");

            string subject = Path.Combine(DirectoryPath, "subject.json");
            File.WriteAllText(subject, JsonSerializer.Serialize(new { id = Holder.Did, membership = "active" }));
            var issue = new CredentialCommands.Vc11IssueParameters(
                Issuer.Did, IssuerName, CredentialId, Holder.Did,
                CredentialType, Context.AbsoluteUri, subject,
                DateTimeOffset.UtcNow.AddSeconds(-30).ToString("O"),
                DateTimeOffset.UtcNow.AddMinutes(6).ToString("O"), CredentialFile);
            using var seed = SeedInput(Issuer.Seed);
            Assert.True(CredentialCommands.TryIssueVc11DidKey(issue, seed));
        }


        internal string IssueStatus(bool revoked = false, bool foreignIssuer = false)
        {
            var signer = foreignIssuer ? Identity() : Issuer;
            string manifest = Path.Combine(DirectoryPath,
                "status-manifest-" + Guid.NewGuid().ToString("N") + ".json");
            string snapshot = Path.Combine(DirectoryPath,
                "status-" + Guid.NewGuid().ToString("N") + ".jwt");
            string[] revokedJwts = revoked
                ? [File.ReadAllText(CredentialFile).TrimEnd('\r', '\n')]
                : [];
            File.WriteAllText(manifest, JsonSerializer.Serialize(revokedJwts));
            using var seed = SeedInput(signer.Seed);
            Assert.True(CredentialCommands.TryIssueVc11DidKeyStatus(
                new(signer.Did, manifest, snapshot,
                    DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O")),
                seed, TimeProvider.System));
            return snapshot;
        }

        internal bool IssueRequest(int lifetimeSeconds = 120)
        {
            using var seed = SeedInput(Verifier.Seed);
            return CredentialCommands.TryCreateVc11VerifierRequest(
                new(Verifier.Did, Tenant.ToString("D"), Audience, Issuer.Did,
                    CredentialType, Context.AbsoluteUri, RequestFile, SessionFile,
                    lifetimeSeconds), seed);
        }

        internal bool Present()
        {
            using var seed = SeedInput(Holder.Seed);
            return CredentialCommands.TryPresentVc11DidKey(
                new(RequestFile, CredentialFile, Verifier.Did, Audience, Issuer.Did,
                    IssuerName, CredentialId, Holder.Did, CredentialType, Context.AbsoluteUri,
                    VpFile, true), seed);
        }

        internal CredentialCommands.Vc11VerifierCheckParameters Check() =>
            new(Verifier.Did, Tenant.ToString("D"), Audience, Issuer.Did,
                CredentialType, Context.AbsoluteUri, RequestFile, SessionFile, VpFile);

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

        public void Dispose() => Directory.Delete(DirectoryPath, recursive: true);
    }
}
