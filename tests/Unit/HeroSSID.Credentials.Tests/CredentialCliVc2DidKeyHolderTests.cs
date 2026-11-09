using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Test-first separate issuer, holder and verifier signed VC2 flow.
/// The CLI must never conflate the issuer's statement with holder proof.
/// </summary>
public sealed class CredentialCliVc2DidKeyHolderTests
{
    [Fact]
    public void RealHolderProofContainsOriginalCredentialAndBoundRequestAndConsumesOnce()
    {
        using var scenario = new Scenario();
        using (var input = Scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.True(CredentialCommands.TryPresentVc2DidKey(scenario.Policy(), input));
        }

        string signedPresentation = File.ReadAllText(scenario.PresentationFile).TrimEnd('\r', '\n');
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(signedPresentation));
        JsonElement claims = document.RootElement;
        Assert.Equal(scenario.Holder.Did, claims.GetProperty("holder").GetString());
        Assert.Equal("data:application/vc+jwt," + scenario.CredentialJwt,
            claims.GetProperty("verifiableCredential")[0].GetProperty("id").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(scenario.RequestJwt))),
            claims.GetProperty("herossidRequestSha256").GetString());

        Assert.Equal(Vcdm20PresentationCheckResult.SignedButStatusUnchecked,
            scenario.Verify(signedPresentation));
        Assert.Equal(Vcdm20PresentationCheckResult.Invalid, scenario.Verify(signedPresentation));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(scenario.PresentationFile));
        }
    }

    [Fact]
    public void ForeignHolderSeedOrWrongIssuerVerifierAndHolderPinsCannotDisclose()
    {
        using var scenario = new Scenario();
        var foreign = Scenario.Identity();
        try
        {
            using (var input = Scenario.SeedInput(foreign.Seed))
            {
                Assert.False(CredentialCommands.TryPresentVc2DidKey(scenario.Policy(), input));
            }

            var incorrect = new[]
            {
                scenario.Policy() with { TrustedIssuerDid = foreign.Did },
                scenario.Policy() with { TrustedVerifierDid = foreign.Did },
                scenario.Policy() with { HolderDid = foreign.Did }
            };
            foreach (var policy in incorrect)
            {
                using var input = Scenario.SeedInput(scenario.Holder.Seed);
                Assert.False(CredentialCommands.TryPresentVc2DidKey(policy, input));
            }

            Assert.False(File.Exists(scenario.PresentationFile));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(foreign.Seed);
        }
    }

    [Fact]
    public void ForgedIssuerCredentialAndVerifierRequestAreRejectedBeforeDisclosure()
    {
        using var scenario = new Scenario();
        string badCredential = Path.Combine(scenario.DirectoryPath, "forged-credential.jwt");
        string badRequest = Path.Combine(scenario.DirectoryPath, "forged-request.jwt");
        File.WriteAllText(badCredential, TamperSignature(scenario.CredentialJwt));
        File.WriteAllText(badRequest, TamperSignature(scenario.RequestJwt));
        using (var input = Scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2DidKey(
                scenario.Policy() with { CredentialJwtFile = badCredential }, input));
        }

        using (var input = Scenario.SeedInput(scenario.Holder.Seed))
        {
            Assert.False(CredentialCommands.TryPresentVc2DidKey(
                scenario.Policy() with { RequestJwtFile = badRequest }, input));
        }

        Assert.False(File.Exists(scenario.PresentationFile));
    }

    [Fact]
    public void WrongTypeContextOrRecipientAndMissingDisclosureApprovalFailClosed()
    {
        using var scenario = new Scenario();
        var invalid = new[]
        {
            scenario.Policy() with { CredentialType = "AnotherCredential" },
            scenario.Policy() with { Context = "https://issuer.example/vocab/other/v1" },
            scenario.Policy() with { Audience = "https://other.example/check" },
            scenario.Policy() with { FullDisclosureAcknowledged = false }
        };
        foreach (var policy in invalid)
        {
            using var input = Scenario.SeedInput(scenario.Holder.Seed);
            Assert.False(CredentialCommands.TryPresentVc2DidKey(policy, input));
        }

        Assert.False(File.Exists(scenario.PresentationFile));
    }

    [Fact]
    public void ExistingOutputIsNeverOverwritten()
    {
        using var scenario = new Scenario();
        File.WriteAllText(scenario.PresentationFile, "preserve me");
        using var input = Scenario.SeedInput(scenario.Holder.Seed);
        Assert.False(CredentialCommands.TryPresentVc2DidKey(scenario.Policy(), input));
        Assert.Equal("preserve me", File.ReadAllText(scenario.PresentationFile));
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
        private const string Audience = "https://verifier.example/credential-check";
        private const string Type = "MembershipCredential";
        private const string ContextText = "https://issuer.example/vocab/membership/v1";
        private static readonly Uri Context = new(ContextText);
        internal readonly (byte[] Seed, string Did) Issuer = Identity();
        internal readonly (byte[] Seed, string Did) Holder = Identity();
        internal readonly (byte[] Seed, string Did) Verifier = Identity();
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-holder-cli-" + Guid.NewGuid().ToString("N"));
        internal readonly string PresentationFile;
        internal readonly string RequestJwt;
        internal readonly string CredentialJwt;
        private readonly string _requestFile;
        private readonly string _credentialFile;
        private readonly Guid _tenantId = Guid.NewGuid();
        private readonly InMemoryPresentationChallengeStore _store =
            new(TimeProvider.System);
        private readonly PresentationChallenge _issuedChallenge;

        internal Scenario()
        {
            Directory.CreateDirectory(DirectoryPath);
            PresentationFile = Path.Combine(DirectoryPath, "holder-vp.jwt");
            _requestFile = Path.Combine(DirectoryPath, "verifier-request.jwt");
            _credentialFile = Path.Combine(DirectoryPath, "credential.jwt");
            _issuedChallenge = _store.Issue(_tenantId, Audience, Issuer.Did,
                TimeSpan.FromMinutes(2));
            var boundRequest = _issuedChallenge with
            {
                CredentialType = Type,
                SubjectContextUri = Context
            };
            RequestJwt = OfflineSignedPresentationRequest.Create(
                boundRequest, Verifier.Did, Verifier.Seed, TimeProvider.System);
            using var subject = JsonDocument.Parse(
                JsonSerializer.Serialize(new { id = Holder.Did, membership = "active" }));
            CredentialJwt = Vcdm20JoseCredential.Create(
                Issuer.Did, Holder.Did, Type, Context, subject.RootElement,
                Issuer.Seed, DateTimeOffset.UtcNow.AddSeconds(-5),
                DateTimeOffset.UtcNow.AddMinutes(4));
            File.WriteAllText(_requestFile, RequestJwt);
            File.WriteAllText(_credentialFile, CredentialJwt);
        }

        internal CredentialCommands.Vc2DidKeyHolderParameters Policy() =>
            new(_requestFile, _credentialFile, Verifier.Did, Audience,
                Issuer.Did, Holder.Did, Type, ContextText,
                PresentationFile, true);

        internal Vcdm20PresentationCheckResult Verify(string presentation) =>
            Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                presentation, RequestJwt,
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(RequestJwt))),
                Verifier.Did, _tenantId, Audience, _issuedChallenge.Nonce,
                Type, Context, _store, TimeProvider.System, out _);

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
            CryptographicOperations.ZeroMemory(Holder.Seed);
            CryptographicOperations.ZeroMemory(Verifier.Seed);
            Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
