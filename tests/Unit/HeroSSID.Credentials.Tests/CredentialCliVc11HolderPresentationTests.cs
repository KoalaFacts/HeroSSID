using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A non-SDK holder must sign a real nested VC1.1 presentation with its own
/// Ed25519 key only after authenticating verifier, issuer and disclosure policy.
/// A presentation is not consent evidence, legal identity or authorization.
/// </summary>
public sealed class CredentialCliVc11HolderPresentationTests
{
    [Fact]
    public void HolderCliSignsOriginalVc11CredentialForOneUseVerifierChallenge()
    {
        using var scenario = new Scenario();
        using var seed = scenario.SeedInput(scenario.Holder.Seed);
        Assert.True(CredentialCommands.TryPresentVc11DidKey(scenario.Policy(), seed));
        string originalVp = File.ReadAllText(scenario.OutputFile).TrimEnd('\r', '\n');
        Assert.DoesNotContain(scenario.OriginalCredential, originalVp, StringComparison.Ordinal);
        // Compact JWT encodes the nested credential in its signed payload.
        using var payload = JsonDocument.Parse(
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractPayload(originalVp));
        Assert.Equal(scenario.OriginalCredential,
            payload.RootElement.GetProperty("vp").GetProperty("verifiableCredential")[0].GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            JwtVcJsonPresentation.Check(originalVp, scenario.Tenant, scenario.Audience,
                scenario.Challenge.Nonce, Scenario.CredentialType, Scenario.Context,
                scenario.Store, TimeProvider.System, out var subject));
        Assert.Equal(scenario.Holder.Did, subject.GetProperty("id").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            JwtVcJsonPresentation.Check(originalVp, scenario.Tenant, scenario.Audience,
                scenario.Challenge.Nonce, Scenario.CredentialType, Scenario.Context,
                scenario.Store, TimeProvider.System, out _));
    }

    [Fact]
    public void HolderSeedAndIndependentlyPinnedVerifierIssuerAndSubjectMustMatch()
    {
        using var scenario = new Scenario();
        var foreign = Scenario.Identity();
        var policy = scenario.Policy();
        using (var seed = scenario.SeedInput(foreign.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(policy, seed));
        }

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { TrustedVerifierDid = foreign.Did }, seed));
        }

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { TrustedIssuerDid = foreign.Did }, seed));
        }

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { IssuerName = "Unapproved Brand" }, seed));
        }

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { CredentialId = "https://issuer.example/credentials/other" }, seed));
        }

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { HolderDid = foreign.Did }, seed));
        }

        Assert.False(File.Exists(scenario.OutputFile));
    }

    [Fact]
    public void ForgedRequestOrCredentialAndUnacknowledgedDisclosureFailClosedWithoutOverwrite()
    {
        using var scenario = new Scenario();
        var policy = scenario.Policy();

        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { FullDisclosureAcknowledged = false }, seed));
        }

        string requestFile = Path.Combine(scenario.DirectoryPath, "forged-request.jwt");
        File.WriteAllText(requestFile, Tamper(scenario.OriginalRequest));
        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { RequestJwtFile = requestFile }, seed));
        }

        string credentialFile = Path.Combine(scenario.DirectoryPath, "forged-vc.jwt");
        File.WriteAllText(credentialFile, Tamper(scenario.OriginalCredential));
        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(
                policy with { CredentialJwtFile = credentialFile }, seed));
        }

        File.WriteAllText(scenario.OutputFile, "must-not-overwrite");
        using (var seed = scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc11DidKey(policy, seed));
        }
        Assert.Equal("must-not-overwrite", File.ReadAllText(scenario.OutputFile));
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
        private const string IssuerName = "Acme Membership Issuer";
        private const string CredentialId = "https://issuer.example/credentials/member-123";
        internal readonly string DirectoryPath = Path.Combine(
            Path.GetTempPath(), "herossid-holder-vp-" + Guid.NewGuid().ToString("N"));
        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Holder = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        internal readonly Guid Tenant = Guid.NewGuid();
        internal readonly InMemoryPresentationChallengeStore Store = new(TimeProvider.System);
        internal readonly string Audience;
        internal readonly PresentationChallenge Challenge;
        internal readonly string OriginalRequest;
        internal readonly string OriginalCredential;
        internal readonly string RequestFile;
        internal readonly string CredentialFile;
        internal readonly string OutputFile;

        internal Scenario()
        {
            Directory.CreateDirectory(DirectoryPath);
            Audience = "decentralized_identifier:" + Verifier.Did;
            Challenge = Store.Issue(Tenant, Audience, Issuer.Did);
            OriginalRequest = OfflineSignedPresentationRequest.Create(
                Challenge, Verifier.Did, Verifier.Seed, TimeProvider.System);
            RequestFile = Path.Combine(DirectoryPath, "request.jwt");
            File.WriteAllText(RequestFile, OriginalRequest);

            string subjectFile = Path.Combine(DirectoryPath, "subject.json");
            CredentialFile = Path.Combine(DirectoryPath, "credential.jwt");
            OutputFile = Path.Combine(DirectoryPath, "presentation.jwt");
            File.WriteAllText(subjectFile, JsonSerializer.Serialize(
                new { id = Holder.Did, membership = "active" }));
            var issue = new CredentialCommands.Vc11IssueParameters(
                Issuer.Did, IssuerName, CredentialId, Holder.Did,
                CredentialType, Context.AbsoluteUri, subjectFile,
                DateTimeOffset.UtcNow.AddSeconds(-30).ToString("O"),
                DateTimeOffset.UtcNow.AddMinutes(6).ToString("O"), CredentialFile);
            using var seed = SeedInput(Issuer.Seed);
            Assert.True(CredentialCommands.TryIssueVc11DidKey(issue, seed));
            OriginalCredential = File.ReadAllText(CredentialFile).TrimEnd('\r', '\n');
        }

        internal CredentialCommands.Vc11HolderPresentationParameters Policy() =>
            new(RequestFile, CredentialFile, Verifier.Did, Audience, Issuer.Did,
                IssuerName, CredentialId, Holder.Did, CredentialType,
                Context.AbsoluteUri, OutputFile, true);

        internal MemoryStream SeedInput(byte[] seed) =>
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
