using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Real HTTP and ephemeral PostgreSQL contract for tenant-owned, short-lived
/// direct VC2 issuance. Does not assert third-party wallet interoperability.
/// </summary>
public sealed class Vcdm20CredentialIssuanceHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");

    [Fact]
    public async Task AuthorizedTenantCanIssueRealDirectVc2ToUnenrolledExternalHolder()
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuer = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        using var issued = await PostAsync("/api/v1/credentials/vcdm20/issue",
            new
            {
                issuerDid = issuer,
                holderDid,
                credentialType = "MembershipCredential",
                subjectContextUri = Vocabulary,
                credentialSubject = new { id = holderDid, membership = "active" },
                validUntil = now.AddMinutes(5)
            }, token).ConfigureAwait(true);
        string credential = await SetupResponse.ReadRequiredStringAsync(
            issued, HttpStatusCode.Created, "Issue direct VC2", "credential").ConfigureAwait(true);
        using var signed = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(credential));
        Assert.False(signed.RootElement.TryGetProperty("vc", out _));
        Assert.Equal("https://www.w3.org/ns/credentials/v2",
            signed.RootElement.GetProperty("@context")[0].GetString());
        Assert.True(Vcdm20JoseCredential.TryVerify(
            credential, issuer, holderDid, "MembershipCredential",
            Vocabulary, DateTimeOffset.UtcNow, out var verifiedSubject));
        Assert.Equal("active", verifiedSubject.GetProperty("membership").GetString());
    }

    [Fact]
    public async Task AnonymousAndWrongScopeCannotSignAndUnknownIssuerDoesNotSign()
    {
        var body = new
        {
            issuerDid = "did:key:zUnknown",
            holderDid = "did:key:zUnknown",
            credentialType = "MembershipCredential",
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = "did:key:zUnknown", membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        };
        using var anonymous = await _client.PostAsJsonAsync(
            "/api/v1/credentials/vcdm20/issue", body).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync("credential:verify").ConfigureAwait(true);
        using var forbidden = await PostAsync("/api/v1/credentials/vcdm20/issue",
            body, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string issueOnly = await GetTokenAsync("credential:issue").ConfigureAwait(true);
        using var missing = await PostAsync("/api/v1/credentials/vcdm20/issue",
            body, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task MismatchedHolderAndOverlongCredentialLifetimeAreRejected()
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuer = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var mismatched = await PostAsync("/api/v1/credentials/vcdm20/issue",
            new
            {
                issuerDid = issuer, holderDid,
                credentialType = "MembershipCredential",
                subjectContextUri = Vocabulary,
                credentialSubject = new { id = issuer, membership = "active" },
                validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, mismatched.StatusCode);

        using var tooLong = await PostAsync("/api/v1/credentials/vcdm20/issue",
            new
            {
                issuerDid = issuer, holderDid,
                credentialType = "MembershipCredential",
                subjectContextUri = Vocabulary,
                credentialSubject = new { id = holderDid, membership = "active" },
                validUntil = DateTimeOffset.UtcNow.AddDays(1)
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
    }

    private async Task<string> CreateDidAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Create issuer DID", "did").ConfigureAwait(true);
    }

    private async Task<string> GetTokenAsync(string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await _client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.OK, "Obtain scoped token", "access_token").ConfigureAwait(true);
    }

    private async Task<HttpResponseMessage> PostAsync<T>(string path, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(request).ConfigureAwait(true);
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
