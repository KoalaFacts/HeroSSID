using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Real HTTP and ephemeral PostgreSQL contract for opt-in VC2 issuer verification.</summary>
public sealed class Vcdm20CredentialVerificationHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task IndependentlyIssuedVc2ReturnsVerifiedSubjectOnlyWithRealSignature()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holder = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string issuerDid = DidFromKey(issuer.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var context = new Uri("https://issuer.example/contexts/membership/v1");
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        var now = DateTimeOffset.UtcNow;
        string token = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", context, subject.RootElement,
            issuer.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(10));
        var verification = new
        {
            Credential = token,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = "MembershipCredential",
            SubjectContextUri = context
        };

        using var anonymous = await _client.PostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify", verification).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var accepted = await _client.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify", verification).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var positive = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", positive.GetProperty("status").GetString());
        Assert.Equal("member", positive.GetProperty("verifiedSubject").GetProperty("role").GetString());

        var parts = token.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(token).Replace("member", "admin",
                StringComparison.Ordinal));
        using var forged = await _client.AuthorizedPostAsJsonAsync(
            "/api/v1/credentials/vcdm20/verify",
            new
            {
                Credential = string.Join('.', parts),
                TrustedIssuerDid = issuerDid,
                ExpectedHolderDid = holderDid,
                ExpectedCredentialType = "MembershipCredential",
                SubjectContextUri = context
            }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, forged.StatusCode);
        var rejected = await forged.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);
    }

    private static string DidFromKey(byte[] key)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        key.CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
