using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonExactStatusObservationTests
{
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly DateTimeOffset Epoch = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void GenuinePostIncidentObservationWithinSameSecondCanBeAccepted()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset observed = Epoch.AddTicks(3_750_000);
        string credential = Issue(issuer, holder, observed);
        string snapshot = JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, [], issuer.Seed, observed, new FixedClock(observed));

        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(snapshot));
        Assert.Equal(ToNumericDate(observed), payload.RootElement.GetProperty("iat").GetDecimal());
        Assert.Equal(ToNumericDate(observed.AddSeconds(60)),
            payload.RootElement.GetProperty("exp").GetDecimal());

        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(snapshot, credential,
                issuer.Did, observed.AddMilliseconds(100), observed.AddMilliseconds(-50)));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(snapshot, credential,
                issuer.Did, observed.AddMilliseconds(100), observed.AddTicks(1)));
    }

    [Fact]
    public void FutureStatusAndExactExpirationBoundaryNeverReleaseNotListed()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset observed = Epoch.AddTicks(3_750_000);
        string credential = Issue(issuer, holder, observed);
        string snapshot = JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, [], issuer.Seed, observed, new FixedClock(observed));

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
                issuer.Did, observed.AddTicks(-1)));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential, issuer.Did, observed));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
                issuer.Did, observed.AddSeconds(60).AddTicks(-1)));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
                issuer.Did, observed.AddSeconds(60)));
    }

    [Fact]
    public void GenuineFractionalStatusStillRequiresOriginalIssuerSignature()
    {
        var issuer = NewIdentity();
        var foreign = NewIdentity();
        var holder = NewIdentity();
        DateTimeOffset observed = Epoch.AddTicks(3_750_000);
        string credential = Issue(issuer, holder, observed);
        string snapshot = JwtVcJsonRevocationSnapshot.Create(
            issuer.Did, [], issuer.Seed, observed, new FixedClock(observed));
        string[] pieces = snapshot.Split('.');
        pieces[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(snapshot).Replace(
                "revoked", "forged", StringComparison.Ordinal));

        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(string.Join('.', pieces), credential,
                issuer.Did, observed.AddSeconds(1)));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
                foreign.Did, observed.AddSeconds(1)));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
                issuer.Did, observed.AddSeconds(1)));
    }

    private static decimal ToNumericDate(DateTimeOffset time) =>
        (decimal)(time.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) /
        TimeSpan.TicksPerSecond;

    private static string Issue((byte[] Seed, string Did) issuer,
        (byte[] Seed, string Did) holder, DateTimeOffset observed)
    {
        using var subject = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = holder.Did, membership = "active" }));
        return JwtVcJsonCredential.Create(issuer.Did, holder.Did, CredentialType,
            Context, subject.RootElement, issuer.Seed,
            observed.AddMinutes(-1), observed.AddMinutes(10));
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
