using System.CommandLine;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Real issuer, holder and verifier signing keys; local verifier alone owns
/// the signed request, exact original digest and atomic single-use state.
/// </summary>
public sealed class CredentialCliVc2DidKeyVerifierSessionTests
{
    [Fact]
    public void GenuineOriginalCredentialAndHolderProofAreAcceptedOnlyOnce()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        Assert.True(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(scenario.Check()));
        Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(scenario.Check()));
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.True(File.Exists(scenario.SessionFile + ".used"));
    }

    [Fact]
    public void ForgedRequestOrPresentationAndWrongTrustPinsNeverSpendChallenge()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());

        var check = scenario.Check();
        var foreignIssuer = Scenario.Identity();
        var foreignVerifier = Scenario.Identity();
        try
        {
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(
                check with { TrustedIssuerDid = foreignIssuer.Did }));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(
                check with { VerifierDid = foreignVerifier.Did }));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(
                check with { CredentialType = "OtherCredential" }));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(
                check with { Audience = "https://other.example/credential-check" }));

            string originalRequest = File.ReadAllText(scenario.RequestFile);
            File.WriteAllText(scenario.RequestFile, Tamper(originalRequest.Trim()));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(check));
            File.WriteAllText(scenario.RequestFile, originalRequest);

            string originalVp = File.ReadAllText(scenario.PresentationFile);
            File.WriteAllText(scenario.PresentationFile, Tamper(originalVp.Trim()));
            Assert.False(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(check));
            File.WriteAllText(scenario.PresentationFile, originalVp);

            Assert.True(File.Exists(scenario.SessionFile));
            Assert.False(File.Exists(scenario.SessionFile + ".used"));
            Assert.True(CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(check));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(foreignIssuer.Seed);
            CryptographicOperations.ZeroMemory(foreignVerifier.Seed);
        }
    }

    [Fact]
    public async Task ParallelVerificationOnlyConsumesOneSingleMachineChallenge()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        var policy = scenario.Check();
        bool[] results = await Task.WhenAll(
            Task.Run(() => CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(policy)),
            Task.Run(() => CredentialCommands.TryVerifyVc2DidKeyVerifierPresentation(policy)));
        Assert.Single(results, static accepted => accepted);
    }

    [Fact]
    public void RejectsNoncanonicalRecipientAndNeverOverwritesVerifierFiles()
    {
        using var scenario = new Scenario();
        Assert.False(scenario.IssueRequest(audience: "http://verifier.example/check"));
        Assert.False(File.Exists(scenario.SessionFile));
        Assert.False(File.Exists(scenario.RequestFile));
        Assert.False(scenario.IssueRequest(lifetime: 301));

        File.WriteAllText(scenario.RequestFile, "keep original");
        Assert.False(scenario.IssueRequest());
        Assert.Equal("keep original", File.ReadAllText(scenario.RequestFile));
        Assert.False(File.Exists(scenario.SessionFile));
    }

    [Fact]
    public async Task RegisteredOfflineVerifierCommandRejectsReplayWithoutDisclosingClaims()
    {
        using var scenario = new Scenario();
        Assert.True(scenario.IssueRequest());
        Assert.True(scenario.Present());
        string[] args =
        [
            "verify-vc2-didkey-vp",
            "--verifier-did", scenario.Verifier.Did,
            "--tenant-id", scenario.Tenant.ToString("D"),
            "--audience", scenario.Audience,
            "--trusted-issuer", scenario.Issuer.Did,
            "--credential-type", Scenario.Type,
            "--context", Scenario.Context.AbsoluteUri,
            "--request-jwt-file", scenario.RequestFile,
            "--session-file", scenario.SessionFile,
            "--presentation-jwt-file", scenario.PresentationFile
        ];
        Assert.Equal(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(args).ConfigureAwait(true));
        Assert.NotEqual(0, await CredentialCommands.CreateCommand(null!)
            .InvokeAsync(args).ConfigureAwait(true));
    }

    private static string Tamper(string jwt)
    {
        string[] segments = jwt.Split('.');
        Assert.Equal(3, segments.Length);
        segments[2] = (segments[2][0] == 'A' ? "B" : "A") + segments[2][1..];
        return string.Join('.', segments);
    }

    private sealed class Scenario : IDisposable
    {
        internal const string Type = "MembershipCredential";
        internal static readonly Uri Context = new("https://issuer.example/vocab/membership/v1");
        internal readonly Guid Tenant = Guid.NewGuid();
        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Holder = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-verifier-" + Guid.NewGuid().ToString("N"));
        internal readonly string Audience = "https://verifier.example/credential-check";
        internal readonly string RequestFile;
        internal readonly string SessionFile;
        internal readonly string PresentationFile;
        private readonly string _credentialFile;

        internal Scenario()
        {
            Directory.CreateDirectory(DirectoryPath);
            RequestFile = Path.Combine(DirectoryPath, "signed-request.jwt");
            SessionFile = Path.Combine(DirectoryPath, "private-session.json");
            PresentationFile = Path.Combine(DirectoryPath, "holder-vp.jwt");
            _credentialFile = Path.Combine(DirectoryPath, "issuer-vc2.jwt");

            using var subject = JsonDocument.Parse(
                JsonSerializer.Serialize(new { id = Holder.Did, membership = "active" }));
            string jwt = Vcdm20JoseCredential.Create(
                Issuer.Did, Holder.Did, Type, Context, subject.RootElement,
                Issuer.Seed, DateTimeOffset.UtcNow.AddSeconds(-10),
                DateTimeOffset.UtcNow.AddMinutes(5));
            File.WriteAllText(_credentialFile, jwt);
        }

        internal bool IssueRequest(int lifetime = 120, string? audience = null)
        {
            using var seed = SeedInput(Verifier.Seed);
            return CredentialCommands.TryCreateVc2DidKeyVerifierRequest(
                new CredentialCommands.Vc11VerifierRequestParameters(
                    Verifier.Did, Tenant.ToString("D"), audience ?? Audience,
                    Issuer.Did, Type, Context.AbsoluteUri,
                    RequestFile, SessionFile, lifetime), seed);
        }

        internal bool Present()
        {
            using var seed = SeedInput(Holder.Seed);
            return CredentialCommands.TryPresentVc2DidKey(
                new CredentialCommands.Vc2DidKeyHolderParameters(
                    RequestFile, _credentialFile, Verifier.Did, Audience,
                    Issuer.Did, Holder.Did, Type, Context.AbsoluteUri,
                    PresentationFile, true), seed);
        }

        internal CredentialCommands.Vc11VerifierCheckParameters Check() =>
            new(Verifier.Did, Tenant.ToString("D"), Audience, Issuer.Did,
                Type, Context.AbsoluteUri, RequestFile, SessionFile, PresentationFile);

        private static MemoryStream SeedInput(byte[] seed) =>
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
            CryptographicOperations.ZeroMemory(Holder.Seed);
            CryptographicOperations.ZeroMemory(Verifier.Seed);
            Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
