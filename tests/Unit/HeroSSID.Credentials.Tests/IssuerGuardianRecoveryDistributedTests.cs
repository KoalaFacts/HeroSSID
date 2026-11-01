using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class IssuerGuardianRecoveryDistributedTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Audience = new("https://verifier.example/recover-issuer");
    private const string Nonce = "distributed_guardians_20261101_ABCDEF";

    [Fact]
    public void IndependentGuardianSignaturesCanBeAssembledWithoutExportingSeedsToCoordinator()
    {
        var oldIssuer = NewKey();
        var successor = NewKey();
        var guardianOne = NewKey();
        var guardianTwo = NewKey();
        var guardianThree = NewKey();
        string signedProposal = Proposal(oldIssuer.Did, successor);
        string first = Approve(signedProposal, oldIssuer.Did, successor.Did, guardianOne);
        string second = Approve(signedProposal, oldIssuer.Did, successor.Did, guardianTwo);
        string envelope = IssuerGuardianRecoveryDistributed.AssembleEvidence(signedProposal, [first, second]);

        Assert.True(IssuerGuardianRecovery.TryVerify(envelope, oldIssuer.Did,
            [guardianOne.Did, guardianTwo.Did, guardianThree.Did], 2,
            Audience, Nonce, Now, out string verified));
        Assert.Equal(successor.Did, verified);
        Assert.DoesNotContain(Convert.ToBase64String(guardianOne.Seed), envelope, StringComparison.Ordinal);
    }

    [Fact]
    public void GuardianRejectsProposalWithWrongIndependentlyExpectedIssuerOrSuccessor()
    {
        var oldIssuer = NewKey();
        var successor = NewKey();
        var other = NewKey();
        var guardian = NewKey();
        string proposal = Proposal(oldIssuer.Did, successor);

        Assert.False(TryApprove(proposal, other.Did, successor.Did, guardian, Audience, Nonce, Now, out string wrongOld));
        Assert.Equal(string.Empty, wrongOld);
        Assert.False(TryApprove(proposal, oldIssuer.Did, other.Did, guardian, Audience, Nonce, Now, out string wrongNew));
        Assert.Equal(string.Empty, wrongNew);
    }

    [Fact]
    public void GuardianRejectsWrongAudienceNonceOrExpiredProposal()
    {
        var oldIssuer = NewKey();
        var successor = NewKey();
        var guardian = NewKey();
        string proposal = Proposal(oldIssuer.Did, successor);

        Assert.False(TryApprove(proposal, oldIssuer.Did, successor.Did, guardian,
            new Uri("https://attacker.example/approve"), Nonce, Now, out _));
        Assert.False(TryApprove(proposal, oldIssuer.Did, successor.Did, guardian,
            Audience, "another_distributed_guardians_nonce", Now, out _));
        Assert.False(TryApprove(proposal, oldIssuer.Did, successor.Did, guardian,
            Audience, Nonce, Now.AddMinutes(5), out _));
        Assert.False(TryApprove(proposal, oldIssuer.Did, successor.Did, guardian,
            Audience, Nonce, Now.AddTicks(-1), out _));
    }

    [Fact]
    public void GuardianRejectsInvalidSignatureOrUnrelatedPrivateSeed()
    {
        var oldIssuer = NewKey();
        var successor = NewKey();
        var guardian = NewKey();
        var impostor = NewKey();
        string proposal = Proposal(oldIssuer.Did, successor);
        var segments = proposal.Split('.');
        string tampered = segments[0] + "." + segments[1][..^1] +
            (segments[1][^1] == 'A' ? "B" : "A") + "." + segments[2];

        Assert.False(TryApprove(tampered, oldIssuer.Did, successor.Did, guardian,
            Audience, Nonce, Now, out _));
        Assert.False(IssuerGuardianRecoveryDistributed.TryCreateGuardianApproval(
            proposal, oldIssuer.Did, successor.Did, guardian.Did, impostor.Seed,
            Audience, Nonce, Now, out string mismatchedSeed));
        Assert.Equal(string.Empty, mismatchedSeed);
        Assert.False(TryApprove(proposal, oldIssuer.Did, successor.Did, successor,
            Audience, Nonce, Now, out _));
    }

    [Fact]
    public void ReplayedOrMixedGuardianApprovalsDoNotProduceIndependentQuorum()
    {
        var oldIssuer = NewKey();
        var successor = NewKey();
        var firstGuardian = NewKey();
        var secondGuardian = NewKey();
        string proposal = Proposal(oldIssuer.Did, successor);
        string first = Approve(proposal, oldIssuer.Did, successor.Did, firstGuardian);
        string replay = IssuerGuardianRecoveryDistributed.AssembleEvidence(proposal, [first, first]);
        Assert.False(IssuerGuardianRecovery.TryVerify(replay, oldIssuer.Did,
            [firstGuardian.Did, secondGuardian.Did], 2, Audience, Nonce, Now, out _));

        string secondProposal = IssuerGuardianRecoveryDistributed.CreateSuccessorSignature(
            oldIssuer.Did, successor.Did, successor.Seed, Audience,
            "other_distributed_guardians_20261101", new FixedClock(Now));
        string second = Approve(secondProposal, oldIssuer.Did, successor.Did, secondGuardian,
            "other_distributed_guardians_20261101");
        string mixed = IssuerGuardianRecoveryDistributed.AssembleEvidence(proposal, [first, second]);
        Assert.False(IssuerGuardianRecovery.TryVerify(mixed, oldIssuer.Did,
            [firstGuardian.Did, secondGuardian.Did], 2, Audience, Nonce, Now, out _));
    }

    private static string Proposal(string previousIssuer, (string Did, byte[] Seed) successor) =>
        IssuerGuardianRecoveryDistributed.CreateSuccessorSignature(previousIssuer,
            successor.Did, successor.Seed, Audience, Nonce, new FixedClock(Now));

    private static string Approve(string proposal, string previousIssuer, string successor,
        (string Did, byte[] Seed) guardian, string nonce = Nonce)
    {
        Assert.True(TryApprove(proposal, previousIssuer, successor, guardian,
            Audience, nonce, Now, out string approval));
        return approval;
    }

    private static bool TryApprove(string proposal, string previousIssuer, string successor,
        (string Did, byte[] Seed) guardian, Uri audience, string nonce, DateTimeOffset now,
        out string approval) =>
        IssuerGuardianRecoveryDistributed.TryCreateGuardianApproval(proposal,
            previousIssuer, successor, guardian.Did, guardian.Seed,
            audience, nonce, now, out approval);

    private static (string Did, byte[] Seed) NewKey()
    {
        var options = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] rawPublic = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var keyBytes = new byte[34];
        keyBytes[0] = 0xed;
        keyBytes[1] = 0x01;
        rawPublic.CopyTo(keyBytes, 2);
        return ("did:key:z" + SimpleBase.Base58.Bitcoin.Encode(keyBytes),
            key.Export(KeyBlobFormat.RawPrivateKey));
    }

    private sealed class FixedClock(DateTimeOffset time) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => time;
    }
}
