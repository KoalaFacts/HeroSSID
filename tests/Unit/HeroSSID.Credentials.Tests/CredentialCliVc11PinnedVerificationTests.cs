using System.Text;
using System.Text.Json;
using HeroSSID.Cli.Commands;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Exact independently enrolled issuer metadata pins for original VC1.1 JWTs.
/// Passing issuer verification does not prove holder private-key possession.
/// </summary>
public sealed class CredentialCliVc11PinnedVerificationTests
{
    private const string IssuerName = "Acme Membership Issuer";
    private const string Context = "https://issuer.example/vocab/membership";
    private const string CredentialId = "https://issuer.example/credentials/member-123";

    [Fact]
    public void IssuerCliOutputIsAcceptedOnlyAgainstOriginalIssuerAndExactMetadata()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string original = Issue(directory, "original.jwt", issuer, holder.Did, now);
            var pins = Pins(original, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinned(pins, now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins with { IssuerName = "Unapproved Issuer" }, now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins with { CredentialId = "https://issuer.example/credentials/other" }, now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins with { HolderDid = issuer.Did }, now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins with { Context = "https://issuer.example/vocab/other" }, now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ForeignIssuerAndTamperedOriginalJwtAreRejected()
    {
        var trusted = Identity();
        var foreign = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string issuedByForeign = Issue(directory, "foreign.jwt", foreign, holder.Did, now);
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                Pins(issuedByForeign, trusted.Did, holder.Did), now));

            string original = Issue(directory, "genuine.jwt", trusted, holder.Did, now);
            string[] segments = File.ReadAllText(original).TrimEnd('\r', '\n').Split('.');
            Assert.Equal(3, segments.Length);
            string payload = segments[1];
            segments[1] = (payload[0] == 'A' ? "B" : "A") + payload[1..];
            string tampered = Path.Combine(directory, "tampered.jwt");
            File.WriteAllText(tampered, string.Join(".", segments));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                Pins(tampered, trusted.Did, holder.Did), now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ExpiryAndOversizedJwtFailClosed()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string original = Issue(directory, "short-lived.jwt", issuer, holder.Did, now);
            var pins = Pins(original, issuer.Did, holder.Did);
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins, now.AddMinutes(30)));

            string oversized = Path.Combine(directory, "oversized.jwt");
            File.WriteAllText(oversized, new string('a', 65_537));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinned(
                pins with { JwtFile = oversized }, now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }


    [Fact]
    public void ExactSignedMembershipStringMatchesVerifierOwnedPolicyOnly()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string jwt = Issue(directory, "claim.jwt", issuer, holder.Did, now);
            var pins = Pins(jwt, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", "active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", "inactive", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "role", "admin", now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void SignedClaimDoesNotOverrideIssuerPinsOrAuthenticateForgedJwt()
    {
        var issuer = Identity();
        var other = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string jwt = Issue(directory, "genuine-claim.jwt", issuer, holder.Did, now);
            var pins = Pins(jwt, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", "active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins with { TrustedIssuer = other.Did }, "membership", "active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins with { IssuerName = "Untrusted Brand" }, "membership", "active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins with { HolderDid = other.Did }, "membership", "active", now));

            string[] segments = File.ReadAllText(jwt).TrimEnd('\r', '\n').Split('.');
            Assert.Equal(3, segments.Length);
            segments[1] = (segments[1][0] == 'A' ? "B" : "A") + segments[1][1..];
            string forged = Path.Combine(directory, "forged-claim.jwt");
            File.WriteAllText(forged, string.Join(".", segments));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins with { JwtFile = forged }, "membership", "active", now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void NonStringClaimsAndUnsafePolicyKeysAreNotAccepted()
    {
        var issuer = Identity();
        var holder = Identity();
        string directory = CreateDirectory();
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string good = Issue(directory, "good-claim.jwt", issuer, holder.Did, now);
            var pins = Pins(good, issuer.Did, holder.Did);
            Assert.True(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", "active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "id", holder.Did, now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", " active", now));
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins, "membership", "", now));

            string nonString = Issue(directory, "non-string.jwt", issuer, holder.Did,
                now, membership: new { level = 1 });
            Assert.False(CredentialCommands.TryVerifyVc11DidKeyPinnedClaim(
                pins with { JwtFile = nonString }, "membership", "active", now));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void PinnedClaimCliPreflightRejectsParserErrorsBeforeTheyEchoPolicyValue()
    {
        string[] valid =
        [
            "credential", "verify-vc11-didkey-pinned-claim",
            "--jwt-file", "synthetic-missing.jwt",
            "--trusted-issuer", "did:key:zSyntheticIssuer",
            "--issuer-name", "Synthetic Issuer",
            "--credential-id", "https://issuer.example/credentials/synthetic",
            "--holder", "did:key:zSyntheticHolder",
            "--credential-type", "MembershipCredential",
            "--context", "https://issuer.example/vocab/synthetic",
            "--claim-name", "membership",
            "--claim-value", "SYNTHETIC_EXPECTED_VALUE_DO_NOT_PRINT"
        ];
        Assert.True(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(valid));

        string[] responseFile = (string[])valid.Clone();
        responseFile[Array.IndexOf(responseFile, "membership")] = "@context";
        Assert.False(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            responseFile));

        string[] duplicate = [.. valid, "--claim-value", "different"];
        Assert.False(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            duplicate));

        string[] unknown = [.. valid, "--unexpected", "surprise"];
        Assert.False(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            unknown));

        string[] optionShapedValue = (string[])valid.Clone();
        optionShapedValue[^1] = "--bad";
        Assert.False(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            optionShapedValue));

        Assert.True(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            ["credential", "verify-vc11-didkey-pinned-claim", "--help"]));
        Assert.True(CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(
            ["credential", "verify-vc11-didkey-pinned"]));
    }

    private static CredentialCommands.Vc11PinnedVerifyParameters Pins(
        string path, string issuerDid, string holderDid) =>
        new(path, issuerDid, IssuerName, CredentialId, holderDid,
            "MembershipCredential", Context);

    private static string Issue(string directory, string filename,
        (byte[] Seed, string Did) issuer, string holderDid, DateTimeOffset now,
        object? membership = null)
    {
        string subject = Path.Combine(directory, filename + ".subject.json");
        string output = Path.Combine(directory, filename);
        File.WriteAllText(subject, JsonSerializer.Serialize(
            new { id = holderDid, membership = membership ?? "active" }));
        var request = new CredentialCommands.Vc11IssueParameters(
            issuer.Did, IssuerName, CredentialId, holderDid,
            "MembershipCredential", Context, subject,
            now.AddMinutes(-1).ToString("O"), now.AddMinutes(8).ToString("O"),
            output);
        using var seedInput = new MemoryStream(
            Encoding.ASCII.GetBytes(Convert.ToHexString(issuer.Seed) + "\n"));
        Assert.True(CredentialCommands.TryIssueVc11DidKey(request, seedInput));
        return output;
    }

    private static string CreateDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(),
            "herossid-vc11-verify-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
