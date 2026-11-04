using System.Reflection;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Verifier-facing release of signed descriptive issuer metadata: an issuer name
/// is a claim, never a substitute for independent issuer trust or holder proof.
/// </summary>
public sealed class JwtVcJsonVerifiedIssuerNameTests
{
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private const string CredentialType = "MembershipCredential";
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NamedCredentialExposesOnlyAuthenticatedIssuerNameAndOriginalCredentialId()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holder.Did, member = true }));
        var credentialId = new Uri("https://issuer.example/credentials/member-0123");
        string jwt = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary, subject.RootElement,
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            "Membership Office", credentialId, exactValidity: true);

        Assert.True(Verify(jwt, issuer.Did, holder.Did,
            out JsonElement claims, out string? id, out string? name));
        Assert.Equal(true, claims.GetProperty("member").GetBoolean());
        Assert.Equal(credentialId.AbsoluteUri, id);
        Assert.Equal("Membership Office", name);
    }

    [Fact]
    public void RejectedAndUnnamedCredentialsNeverExposeUnverifiedIssuerDisplayText()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holder.Did, member = true }));
        string named = JwtVcJsonCredential.CreateWithIssuerName(
            issuer.Did, holder.Did, CredentialType, Vocabulary, subject.RootElement,
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5),
            "Authentic Signer");
        string unnamed = JwtVcJsonCredential.Create(
            issuer.Did, holder.Did, CredentialType, Vocabulary, subject.RootElement,
            issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5));

        Assert.True(Verify(unnamed, issuer.Did, holder.Did,
            out JsonElement unnamedClaims, out string? unnamedId, out string? unnamedName));
        Assert.Equal(true, unnamedClaims.GetProperty("member").GetBoolean());
        Assert.Null(unnamedId);
        Assert.Null(unnamedName);

        Assert.False(Verify(named, outsider.Did, holder.Did,
            out var otherIssuerClaims, out var otherIssuerId, out var otherIssuerName));
        Assert.Equal(JsonValueKind.Undefined, otherIssuerClaims.ValueKind);
        Assert.Null(otherIssuerId);
        Assert.Null(otherIssuerName);

        Assert.False(Verify(named, issuer.Did, outsider.Did,
            out var otherHolderClaims, out var otherHolderId, out var otherHolderName));
        Assert.Equal(JsonValueKind.Undefined, otherHolderClaims.ValueKind);
        Assert.Null(otherHolderId);
        Assert.Null(otherHolderName);

        string[] segments = named.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(named)
                .Replace("Authentic Signer", "Fake Trusted Agency", StringComparison.Ordinal));
        Assert.False(Verify(string.Join('.', segments), issuer.Did, holder.Did,
            out var tamperedClaims, out var tamperedId, out var tamperedName));
        Assert.Equal(JsonValueKind.Undefined, tamperedClaims.ValueKind);
        Assert.Null(tamperedId);
        Assert.Null(tamperedName);

        Assert.False(Verify(named, issuer.Did, holder.Did,
            out var expiredClaims, out var expiredId, out var expiredName, Now.AddMinutes(6)));
        Assert.Equal(JsonValueKind.Undefined, expiredClaims.ValueKind);
        Assert.Null(expiredId);
        Assert.Null(expiredName);
    }

    private static bool Verify(string jwt, string issuerDid, string holderDid,
        out JsonElement subject, out string? id, out string? name, DateTimeOffset? at = null)
    {
        // The new public API is invoked reflectively so a test-only commit
        // compiles against the old SDK and produces genuine runtime RED.
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "TryVerifyWithIssuerName", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        object?[] arguments =
        [
            jwt, issuerDid, holderDid, CredentialType, Vocabulary,
            at ?? Now, default(JsonElement), null, null
        ];
        bool valid = Assert.IsType<bool>(method.Invoke(null, arguments));
        subject = Assert.IsType<JsonElement>(arguments[6]);
        id = arguments[7] as string;
        name = arguments[8] as string;
        return valid;
    }

    private static (byte[] Seed, string Did) NewIdentity()
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
