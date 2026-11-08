using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Operator-managed offline status export must use the actual original issuer
/// JWT, a real signing key, and independently pinned verifier policy.
/// A signed non-listing does not establish a complete or live status feed.
/// </summary>
public sealed class CredentialCliVc2DidWebStatusIssuerTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string IssuerName = "Example Membership Issuer";
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/42");
    private static readonly Uri Audience = new("https://verifier.example/check");
    private static readonly Uri Context = new("https://issuer.example/vocab/member");

    [Theory]
    [InlineData("#key-1")]
    [InlineData("#key-2")]
    public void OriginalJwtStatusExportIsVerifiedByAnIndependentlyPinnedVerifier(string suffix)
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = NewDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string method = IssuerDid + suffix;
            string credential = Credential(issuer, holder.Did, method, now);
            string revokedFile = Path.Combine(directory, "revoked-jwts.txt");
            string output = Path.Combine(directory, "issuer-status.jwt");
            File.WriteAllText(revokedFile, credential + "\n");
            var request = Request(issuer.PublicKey, method, revokedFile, output, now.AddSeconds(-2));
            using var pipe = Pipe(issuer.Seed);

            Assert.True(CredentialCommands.TryIssueVc2DidWebStatus(request, pipe));
            string snapshot = File.ReadAllText(output).TrimEnd('\r', '\n');
            Assert.DoesNotContain(Convert.ToHexString(issuer.Seed), snapshot, StringComparison.Ordinal);
            Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
                Verify(snapshot, credential, issuer.PublicKey, holder.Did, method, now.AddSeconds(-5)));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(output));
            }

            File.WriteAllText(revokedFile, string.Empty);
            string cleanOutput = Path.Combine(directory, "clean-status.jwt");
            using var cleanPipe = Pipe(issuer.Seed);
            Assert.True(CredentialCommands.TryIssueVc2DidWebStatus(
                request with { OutputFile = cleanOutput }, cleanPipe));
            string cleanSnapshot = File.ReadAllText(cleanOutput).TrimEnd('\r', '\n');
            Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
                Verify(cleanSnapshot, credential, issuer.PublicKey, holder.Did, method, now.AddSeconds(-5)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void WrongSignerForgedEntryAndExistingOutputFailClosedWithoutReleasingArtifact()
    {
        var issuer = Identity();
        var attacker = Identity();
        var holder = Identity();
        string directory = NewDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string method = IssuerDid + "#key-1";
            string credential = Credential(issuer, holder.Did, method, now);
            string revokedFile = Path.Combine(directory, "revoked-jwts.txt");
            string output = Path.Combine(directory, "issuer-status.jwt");
            File.WriteAllText(revokedFile, credential + "\n");
            var request = Request(issuer.PublicKey, method, revokedFile, output, now.AddSeconds(-2));

            using (var attackerPipe = Pipe(attacker.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidWebStatus(request, attackerPipe));
            }

            Assert.False(File.Exists(output));
            File.WriteAllText(revokedFile, credential + "tampered\n");
            using (var authenticPipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidWebStatus(request, authenticPipe));
            }

            Assert.False(File.Exists(output));
            File.WriteAllText(revokedFile, credential + "\n");
            File.WriteAllText(output, "do not replace");
            using (var authenticPipe = Pipe(issuer.Seed))
            {
                Assert.False(CredentialCommands.TryIssueVc2DidWebStatus(request, authenticPipe));
            }

            Assert.Equal("do not replace", File.ReadAllText(output));
            using var expiredPipe = Pipe(issuer.Seed);
            Assert.False(CredentialCommands.TryIssueVc2DidWebStatus(
                request with
                {
                    OutputFile = Path.Combine(directory, "expired.jwt"),
                    ObservedAt = now.AddMinutes(-2).ToString("O")
                }, expiredPipe));
            Assert.False(File.Exists(Path.Combine(directory, "expired.jwt")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CredentialCommands.Vc2DidWebStatusIssueParameters Request(
        byte[] publicKey, string method, string revokedFile, string output, DateTimeOffset observedAt) =>
        new(IssuerDid, method, Convert.ToHexString(publicKey), IssuerName,
            revokedFile, observedAt.ToString("O"), output);

    private static Vcdm20RevocationCheckResult Verify(
        string snapshot, string credential, byte[] key, string holder, string method,
        DateTimeOffset minObserved) =>
        Vcdm20PinnedDidWebIssuerStatus.Check(snapshot, credential, IssuerDid,
            method, key, IssuerName, CredentialId, Audience, holder,
            "MembershipCredential", Context, minObserved, DateTimeOffset.UtcNow, out _);

    private static string Credential(
        (byte[] Seed, byte[] PublicKey, string Did) issuer, string holder, string method,
        DateTimeOffset now)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder, membership = "active" }));
        return Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
            IssuerDid, method, issuer.Seed, issuer.PublicKey, IssuerName,
            CredentialId, Audience, holder, "MembershipCredential", Context,
            subject.RootElement, now.AddMinutes(-1), now.AddMinutes(10));
    }

    private static MemoryStream Pipe(byte[] seed) =>
        new(Encoding.ASCII.GetBytes(Convert.ToHexString(seed) + "\n"));

    private static string NewDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(),
            "herossid-vc2-status-issuer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
