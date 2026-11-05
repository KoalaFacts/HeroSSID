using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class Vcdm20TrustedIssuerSignedIdTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 8, 0, 0, TimeSpan.Zero);
    private static readonly Uri Vocabulary = new("https://issuer.example/context/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/serial-12");
    private static readonly Uri OtherCredentialId = new("https://issuer.example/credentials/serial-99");
    private const string CredentialType = "MembershipCredential";
    private readonly (byte[] Seed, string Did) _first = NewIdentity();
    private readonly (byte[] Seed, string Did) _successor = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _stranger = NewIdentity();

    [Fact]
    public void HistoricalAndCurrentIssuerSignaturesAreAcceptedOnlyWithExactCredentialIdPin()
    {
        string[] independentlyPinnedIssuers = [_first.Did, _successor.Did];
        foreach (var signer in new[] { _first, _successor })
        {
            string jwt = IssueWithId(signer);
            Assert.True(Vcdm20TrustedIssuerVerifier.TryVerifyWithId(
                jwt, independentlyPinnedIssuers, _holder.Did, CredentialType,
                Vocabulary, CredentialId, Now, out string actualIssuer, out var subject));
            Assert.Equal(signer.Did, actualIssuer);
            Assert.Equal(_holder.Did, subject.GetProperty("id").GetString());
            Assert.Equal("active", subject.GetProperty("membership").GetString());

            // A signed identifier is an explicit opt-in: legacy six-field verification stays strict.
            Assert.False(Vcdm20TrustedIssuerVerifier.TryVerify(
                jwt, independentlyPinnedIssuers, _holder.Did, CredentialType,
                Vocabulary, Now, out _, out _));
        }
    }

    [Fact]
    public void DifferentCredentialIdOrDifferentHolderCannotReleaseSubjectOrIssuer()
    {
        string jwt = IssueWithId(_first);
        foreach (var policy in new[]
        {
            (Holder: _holder.Did, Id: OtherCredentialId),
            (Holder: _stranger.Did, Id: CredentialId),
            (Holder: _holder.Did, Id: new Uri("http://issuer.example/credentials/serial-12"))
        })
        {
            Assert.False(Vcdm20TrustedIssuerVerifier.TryVerifyWithId(
                jwt, [_first.Did], policy.Holder, CredentialType,
                Vocabulary, policy.Id, Now, out string issuer, out var subject));
            Assert.Equal(string.Empty, issuer);
            Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        }
    }

    [Fact]
    public void UntrustedSignerAndInvalidOrAmbiguousTrustPolicyFailClosed()
    {
        string jwt = IssueWithId(_first);
        foreach (string[] trust in new[]
        {
            new[] { _successor.Did },
            new[] { _first.Did, _first.Did },
            new[] { _first.Did, "did:key:not-valid" },
            Array.Empty<string>()
        })
        {
            Assert.False(Vcdm20TrustedIssuerVerifier.TryVerifyWithId(
                jwt, trust, _holder.Did, CredentialType,
                Vocabulary, CredentialId, Now, out string issuer, out var subject));
            Assert.Equal(string.Empty, issuer);
            Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        }
    }

    [Fact]
    public void LegacyNoIdTamperedIdAndExpiredSignedIdCannotBePromoted()
    {
        using var subjectJson = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string legacy = Vcdm20JoseCredential.Create(
            _first.Did, _holder.Did, CredentialType, Vocabulary, subjectJson.RootElement,
            _first.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
        string valid = IssueWithId(_first);
        string[] parts = valid.Split('.');
        string payload = Ed25519JwtSigner.ExtractPayload(valid);
        string changed = payload.Replace("serial-12", "serial-99", StringComparison.Ordinal);
        Assert.NotEqual(payload, changed);
        parts[1] = Base64UrlEncoder.Encode(changed);
        string tampered = string.Join('.', parts);

        foreach (var candidate in new[]
        {
            (Jwt: legacy, When: Now),
            (Jwt: tampered, When: Now),
            (Jwt: valid, When: Now.AddHours(1))
        })
        {
            Assert.False(Vcdm20TrustedIssuerVerifier.TryVerifyWithId(
                candidate.Jwt, [_first.Did], _holder.Did, CredentialType,
                Vocabulary, CredentialId, candidate.When,
                out string issuer, out var subject));
            Assert.Equal(string.Empty, issuer);
            Assert.Equal(JsonValueKind.Undefined, subject.ValueKind);
        }
    }

    private string IssueWithId((byte[] Seed, string Did) issuer)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return Vcdm20JoseCredential.CreateWithId(
            issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(10), CredentialId);
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        var options = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };
        using var key = Key.Create(SignatureAlgorithm.Ed25519, options);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        publicKey.CopyTo(encoded, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded));
    }
}
