using System.CommandLine;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Offline no-SDK VC2 agent scope verifier: issuer signature is an assertion,
/// never an Agent possession proof or permission to execute an action.
/// </summary>
public sealed class CredentialCliVc2AgentScopeTests
{
    private static readonly Uri Context = new("https://issuer.example/vocab/agent-scope/v1");
    private static readonly Uri Id = new("https://issuer.example/credentials/agent-scope/42");
    private static readonly Uri Recipient = new("https://verifier.example/agent-requests");
    private static readonly Uri Resource = new("https://api.example/projects/42");

    [Fact]
    public async Task IndependentVerifierAcceptsRealIssuerScopeWithoutSdkCaller()
    {
        var issuer = Identity();
        var agent = Identity();
        string file = TemporaryFile();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await File.WriteAllTextAsync(file, Vcdm20AgentScopeAssertion.Create(
                issuer.Did, agent.Did, Context, Id, Recipient, Resource,
                "invoices.read", issuer.Seed, now.AddSeconds(-5), now.AddMinutes(5))).ConfigureAwait(true);
            Assert.Equal(0, await Invoke(file, issuer.Did, agent.Did,
                "invoices.read", Resource.AbsoluteUri).ConfigureAwait(true));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task AnotherGenuineExactScopedCredentialIsAcceptedWithoutGenericClaimDowngrade()
    {
        var issuer = Identity();
        var agent = Identity();
        string file = TemporaryFile();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Uri resource = new("https://api.example/projects/43");
            await File.WriteAllTextAsync(file, Vcdm20AgentScopeAssertion.Create(
                issuer.Did, agent.Did, Context, Id, Recipient, resource,
                "projects:read", issuer.Seed, now.AddSeconds(-5), now.AddMinutes(5))).ConfigureAwait(true);
            Assert.Equal(0, await Invoke(file, issuer.Did, agent.Did,
                "projects:read", resource.AbsoluteUri).ConfigureAwait(true));
            Assert.NotEqual(0, await Invoke(file, issuer.Did, agent.Did,
                "projects:write", resource.AbsoluteUri).ConfigureAwait(true));
            Assert.NotEqual(0, await Invoke(file, issuer.Did, agent.Did,
                "projects:read", Resource.AbsoluteUri).ConfigureAwait(true));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task ForeignIssuerTamperedJwtAndLongLivedSignedScopeAreRejected()
    {
        var issuer = Identity();
        var agent = Identity();
        string file = TemporaryFile();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string original = Vcdm20AgentScopeAssertion.Create(
                issuer.Did, agent.Did, Context, Id, Recipient, Resource,
                "invoices.read", issuer.Seed, now.AddSeconds(-5), now.AddMinutes(5));
            await File.WriteAllTextAsync(file, original);
            Assert.NotEqual(0, await Invoke(file, Identity().Did, agent.Did,
                "invoices.read", Resource.AbsoluteUri).ConfigureAwait(true));
            Assert.NotEqual(0, await Invoke(file, issuer.Did, Identity().Did,
                "invoices.read", Resource.AbsoluteUri).ConfigureAwait(true));

            string[] parts = original.Split('.');
            parts[2] = (parts[2][0] == 'A' ? "B" : "A") + parts[2][1..];
            await File.WriteAllTextAsync(file, string.Join('.', parts));
            Assert.NotEqual(0, await Invoke(file, issuer.Did, agent.Did,
                "invoices.read", Resource.AbsoluteUri).ConfigureAwait(true));

            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                id = agent.Did, action = "invoices.read", resource = Resource.AbsoluteUri
            }));
            await File.WriteAllTextAsync(file, Vcdm20JoseCredential.CreateForAudienceWithId(
                issuer.Did, agent.Did, Vcdm20AgentScopeAssertion.CredentialType,
                Context, subject.RootElement, issuer.Seed,
                now.AddMinutes(-1), now.AddHours(1), Id, Recipient)).ConfigureAwait(true);
            Assert.NotEqual(0, await Invoke(file, issuer.Did, agent.Did,
                "invoices.read", Resource.AbsoluteUri).ConfigureAwait(true));
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static Task<int> Invoke(string file, string issuer, string agent,
        string action, string resource) =>
        CredentialCommands.CreateCommand(null!).InvokeAsync(
        [
            "verify-vc2-agent-scope", "--jwt-file", file,
            "--trusted-issuer", issuer, "--agent", agent,
            "--context", Context.AbsoluteUri, "--credential-id", Id.AbsoluteUri,
            "--audience", Recipient.AbsoluteUri, "--resource", resource,
            "--action", action
        ]);

    private static string TemporaryFile() =>
        Path.Combine(Path.GetTempPath(), "herossid-agent-cli-" + Guid.NewGuid().ToString("N") + ".jwt");

    private static (byte[] Seed, string Did) Identity()
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
}
