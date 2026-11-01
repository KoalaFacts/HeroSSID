using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerGuardianRecoveryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Audience = new("https://verifier.example/recover-issuer");
    private const string Nonce = "guardian_nonce_20261101_ABCDEF012345";

    [Fact]
    public void TwoPinnedGuardiansAndNewKeyProveRecoveryWithoutTheOldPrivateKey()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        var g3 = NewKey();
        string evidence = Create(oldKey.Did, newKey, g1, g2);

        Assert.True(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            [g1.Did, g2.Did, g3.Did], 2, Audience, Nonce, Now,
            out string verifiedSuccessor));
        Assert.Equal(newKey.Did, verifiedSuccessor);
        Assert.NotEqual(oldKey.Did, verifiedSuccessor);
    }

    [Fact]
    public void UntrustedSecondGuardianCannotMeetIndependentQuorum()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var pinned = NewKey();
        var anotherPinned = NewKey();
        var attacker = NewKey();
        string evidence = Create(oldKey.Did, newKey, pinned, attacker);

        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            [pinned.Did, anotherPinned.Did], 2, Audience, Nonce, Now, out string candidate));
        Assert.Equal(string.Empty, candidate);
    }

    [Fact]
    public void NewKeyPossessionIsMandatoryAndTheOldKeyCannotApproveItsOwnRecovery()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var wrongKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        Assert.Throws<ArgumentException>(() => IssuerGuardianRecovery.Create(oldKey.Did,
            newKey.Did, wrongKey.Seed, Guardians(g1, g2), Audience, Nonce, Clock()));
        Assert.Throws<ArgumentException>(() => IssuerGuardianRecovery.Create(oldKey.Did,
            oldKey.Did, oldKey.Seed, Guardians(g1, g2), Audience, Nonce, Clock()));
        Assert.Throws<ArgumentException>(() => IssuerGuardianRecovery.Create(oldKey.Did,
            newKey.Did, newKey.Seed, Guardians(oldKey, g2), Audience, Nonce, Clock()));
    }

    [Fact]
    public void WrongVerifierNonceOrPreviousIssuerFailsClosed()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        string evidence = Create(oldKey.Did, newKey, g1, g2);
        string[] guardians = [g1.Did, g2.Did];

        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            guardians, 2, new Uri("https://elsewhere.example/recover"), Nonce, Now, out _));
        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            guardians, 2, Audience, "other_nonce_20261101_ABCDEFG", Now, out _));
        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, newKey.Did,
            guardians, 2, Audience, Nonce, Now, out _));
    }

    [Fact]
    public void CannotSpliceAuthenticGuardianSignaturesFromDifferentChallenges()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        string first = Create(oldKey.Did, newKey, g1, g2);
        string second = IssuerGuardianRecovery.Create(oldKey.Did, newKey.Did,
            newKey.Seed, Guardians(g1, g2), Audience,
            "another_guardian_nonce_20261101", Clock());

        using var firstJson = JsonDocument.Parse(first);
        using var secondJson = JsonDocument.Parse(second);
        string mixed = JsonSerializer.Serialize(new
        {
            successorSignature = firstJson.RootElement.GetProperty("successorSignature").GetString(),
            guardianSignatures = new[]
            {
                firstJson.RootElement.GetProperty("guardianSignatures")[0].GetString(),
                secondJson.RootElement.GetProperty("guardianSignatures")[1].GetString()
            }
        });

        Assert.False(IssuerGuardianRecovery.TryVerify(mixed, oldKey.Did,
            [g1.Did, g2.Did], 2, Audience, Nonce, Now, out _));
    }

    [Fact]
    public void ExpirationAndSubsecondIssueTimeAreEnforced()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        string evidence = Create(oldKey.Did, newKey, g1, g2);
        string[] guardians = [g1.Did, g2.Did];

        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did, guardians,
            2, Audience, Nonce, Now.AddTicks(-1), out _));
        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did, guardians,
            2, Audience, Nonce, Now.AddMinutes(5), out _));
    }

    [Fact]
    public void DuplicateTrustedGuardianOrInvalidThresholdCannotLowerQuorum()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var g1 = NewKey();
        var g2 = NewKey();
        string evidence = Create(oldKey.Did, newKey, g1, g2);

        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            [g1.Did, g1.Did], 2, Audience, Nonce, Now, out _));
        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            [g1.Did, g2.Did], 1, Audience, Nonce, Now, out _));
        Assert.False(IssuerGuardianRecovery.TryVerify(evidence, oldKey.Did,
            [g1.Did, g2.Did], 3, Audience, Nonce, Now, out _));
    }

    private static string Create(string oldDid, (string Did, byte[] Seed) successor,
        (string Did, byte[] Seed) g1, (string Did, byte[] Seed) g2) =>
        IssuerGuardianRecovery.Create(oldDid, successor.Did, successor.Seed,
            Guardians(g1, g2), Audience, Nonce, Clock());

    private static Dictionary<string, byte[]> Guardians(
        (string Did, byte[] Seed) g1, (string Did, byte[] Seed) g2) =>
        new(StringComparer.Ordinal) { [g1.Did] = g1.Seed, [g2.Did] = g2.Seed };

    private static FixedClock Clock() => new(Now);

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        var rawPublic = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        rawPublic.CopyTo(bytes, 2);
        return ("did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes),
            key.Export(KeyBlobFormat.RawPrivateKey));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
