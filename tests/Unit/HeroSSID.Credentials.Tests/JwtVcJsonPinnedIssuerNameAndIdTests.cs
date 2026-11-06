using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// A verifier's independently enrolled issuer name AND credential identifier
/// must match before this profile releases issuer-signed VC1.1 claims.
/// An issuer signature is not holder possession or organisational authority.
/// </summary>
public sealed class JwtVcJsonPinnedIssuerNameAndIdTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member-0151");
    private const string CredentialType = "MembershipCredential";
    private const string IssuerName = "Australasian Membership Office";
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SignedJwtVc11NamedIssuerAndJtiRequireIndependentPinsBeforeClaimRelease()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        string jwt = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(5), IssuerName, CredentialId, exactValidity: false);

        Assert.True(Verify(jwt, issuer.Did, IssuerName, holder.Did, CredentialId,
            Now, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());

        // Both of these are authentically signed by the same real issuer.
        // They must nevertheless fail the relying party's independent policy.
        AssertRejected(jwt, issuer.Did, "Another Organisation", holder.Did,
            CredentialId, Now);
        AssertRejected(jwt, issuer.Did, IssuerName, holder.Did,
            new Uri("https://issuer.example/credentials/member-9999"), Now);
    }

    [Fact]
    public void RejectsSignedMetadataOmissionAndForeignSignerWithoutReleasingClaims()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var otherIssuer = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        string namedWithoutId = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(5), IssuerName);
        string idWithoutName = JwtVcJsonCredential.Create(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(5), CredentialId);
        string foreignSigned = JwtVcJsonCredential.CreateWithIssuerName(
            otherIssuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, otherIssuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(5), IssuerName, CredentialId, exactValidity: false);

        AssertRejected(namedWithoutId, issuer.Did, IssuerName, holder.Did, CredentialId, Now);
        AssertRejected(idWithoutName, issuer.Did, IssuerName, holder.Did, CredentialId, Now);
        AssertRejected(foreignSigned, issuer.Did, IssuerName, holder.Did, CredentialId, Now);
        AssertRejected(foreignSigned, otherIssuer.Did, IssuerName, holder.Did,
            CredentialId, Now, expectedHolderDid: issuer.Did);
    }

    [Fact]
    public void RejectsAlteredSignatureExpiredTokenAndInvalidVerifierCredentialId()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        string jwt = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary,
            subject.RootElement, issuer.Seed, Now.AddMinutes(-1),
            Now.AddMinutes(5), IssuerName, CredentialId, exactValidity: true);

        string[] segments = jwt.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(jwt).Replace(
                "active", "privileged", StringComparison.Ordinal));
        AssertRejected(string.Join('.', segments), issuer.Did, IssuerName, holder.Did,
            CredentialId, Now);
        AssertRejected(jwt, issuer.Did, IssuerName, holder.Did, CredentialId,
            Now.AddMinutes(6));
        AssertRejected(jwt, issuer.Did, IssuerName, holder.Did,
            new Uri("http://issuer.example/credentials/member-0151"), Now);
        AssertRejected(jwt, issuer.Did, IssuerName, holder.Did,
            new Uri("https://person:secret@issuer.example/credentials/member-0151"), Now);
    }

    private static void AssertRejected(string jwt, string issuerDid, string issuerName,
        string holderDid, Uri credentialId, DateTimeOffset now, string? expectedHolderDid = null)
    {
        Assert.False(Verify(jwt, issuerDid, issuerName,
            expectedHolderDid ?? holderDid, credentialId, now, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
    }

    private static bool V    private static bool Verify(string jwt, string issuerDid, string issuerName,
        string holderDid, Uri credentialId, DateTimeOffset now, out JsonElement claims) =>
        JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
            jwt, issuerDid, issuerName, holderDid, CredentialType, Vocabulary,
            credentialId, now, out claims);

] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }
}
