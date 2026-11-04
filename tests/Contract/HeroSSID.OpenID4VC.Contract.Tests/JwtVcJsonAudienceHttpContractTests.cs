using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Real authenticated HTTP contract; not an external-wallet interop test.</summary>
public sealed class JwtVcJsonAudienceHttpContractTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string Path = "/api/v1/credentials/jwt-vc-json/verify-for-audience";
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/credentials");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task AuthorizedRecipientGetsVerifiedClaimsButWrongRecipientAndAnonymousDoNot()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string jwt = JwtVcJsonCredential.CreateForAudience(issuerDid, holderDid,
            CredentialType, Context, JsonSerializer.SerializeToElement(
                new { id = holderDid, role = "member" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1),
            now.AddMinutes(5), Recipient);
        var request = new
        {
            credential = jwt, trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Context, expectedAudience = Recipient
        };

        using var anonymous = await _client.PostAsJsonAsync(Path, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var accepted = await _client.AuthorizedPostAsJsonAsync(Path, request)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var ok = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", ok.GetProperty("status").GetString());
        Assert.Equal("member", ok.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var wrong = await _client.AuthorizedPostAsJsonAsync(Path, new
        {
            request.credential, request.trustedIssuerDid, request.expectedHolderDid,
            request.expectedCredentialType, request.subjectContextUri,
            expectedAudience = new Uri("https://stranger.example/credentials")
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        var body = await wrong.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
    }

    private static string Did(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
