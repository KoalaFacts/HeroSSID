using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Signed recipient-bound VC2 tokens must remain addressable in the original
/// issuer's exact-token revocation snapshot, without admitting arbitrary
/// eighth payload members or noncanonical recipient policies.
/// </summary>
public sealed class Vcdm20RecipientBoundRevocationTests
{
    private static readonly Uri Context = new("https://issuer.example/vocab/member/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member/001");
    private static readonly Uri RecipientA = new("https://verifier-a.example/membership");
    private static readonly Uri RecipientB = new("https://verifier-b.example/membership");

    private readonly (byte[] Seed, string Did) _issuer = Identity();
    private readonly (byte[] Seed, string Did) _holder = Identity();
    private readonly TimeProvider _clock = TimeProvider.System;

    [Fact]
    public void AuthenticRecipientBoundCredentialCanBeRevokedOrNotListedByTheSameIssuer()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string credential = Issue(RecipientA, now);

        string clean = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(clean, credential, _issuer.Did, now));

        string revoked = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [credential], _issuer.Seed, now, _clock);
        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(revoked, credential, _issuer.Did, now));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(revoked, credential, _issuer.Did,
                now.AddSeconds(61)));
    }

    [Fact]
    public void DifferentAuthenticSignedRecipientsRemainDifferentRevocationEntries()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string forA = Issue(RecipientA, now);
        string forB = Issue(RecipientB, now);
        Assert.NotEqual(forA, forB);
        string snapshot = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [forA], _issuer.Seed, now, _clock);

        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(snapshot, forA, _issuer.Did, now));
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(snapshot, forB, _issuer.Did, now));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(snapshot, forB, _holder.Did, now));
    }

    [Theory]
    [InlineData("http")]
    [InlineData("aud-array")]
    [InlineData("unrecognized-extra")]
    [InlineData("missing-id")]
    public void GenuineIssuerSignatureCannotMakeMalformedRecipientBoundVcRevocable(string mutation)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string genuine = Issue(RecipientA, now);
        JsonObject payload = JsonNode.Parse(Ed25519JwtSigner.ExtractPayload(genuine))!.AsObject();
        switch (mutation)
        {
            case "http":
                payload["aud"] = "http://verifier-a.example/membership";
                break;
            case "aud-array":
                payload["aud"] = new JsonArray("https://verifier-a.example/membership");
                break;
            case "unrecognized-extra":
                payload["unverifiedPermission"] = "admin";
                break;
            case "missing-id":
                payload.Remove("id");
                break;
        }

        string malformed = Ed25519JwtSigner.CreateSignedJwt(
            Ed25519JwtSigner.ExtractHeader(genuine), payload.ToJsonString(), _issuer.Seed);
        string clean = Vcdm20RevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, now, _clock);

        Assert.Throws<CryptographicException>(() =>
            Vcdm20RevocationSnapshot.Create(
                _issuer.Did, [malformed], _issuer.Seed, now, _clock));
        Assert.Equal(Vcdm20RevocationCheckResult.Invalid,
            Vcdm20RevocationSnapshot.Check(clean, malformed, _issuer.Did, now));
    }

    private string Issue(Uri recipient, DateTimeOffset now)
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return Vcdm20JoseCredential.CreateForAudienceWithId(
            _issuer.Did, _holder.Did, "MembershipCredential", Context,
            subject.RootElement, _issuer.Seed, now.AddMinutes(-1),
            now.AddMinutes(5), CredentialId, recipient);
    }

    private static (byte[] Seed, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
