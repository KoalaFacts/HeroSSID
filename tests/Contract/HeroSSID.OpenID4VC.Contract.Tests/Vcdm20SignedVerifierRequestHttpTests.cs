using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// HTTP verifier-owned Ed25519 request signing with a real ephemeral PostgreSQL
/// challenge store. The holder independently pins the verifier DID and keeps its seed.
/// This is the HeroSSID VC2 profile, not a third-party wallet compatibility assertion.
/// </summary>
#pragma warning disable CA1515 // Public class is required for xUnit discovery.
public sealed class Vcdm20SignedVerifierRequestHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
#pragma warning restore CA1515
{
    private const string Route = "/api/v1/credentials/vcdm20/signed-presentation-request";
    private const string Audience = "https://verifier.example/receive";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/member/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task OwnedVerifierDidSignsRealRequestThatIndependentHolderCanValidateAndUse()
    {
        string token = await GetTokenAsync("did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var issued = await PostAsync(Route, new
        {
            verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        string requestJwt = await SetupResponse.ReadRequiredStringAsync(
            issued, HttpStatusCode.Created, "Sign verifier-owned request", "signedRequestJwt").ConfigureAwait(true);
        using var body = await issued.Content.ReadFromJsonAsync<JsonDocument>().ConfigureAwait(true);
        Assert.NotNull(body);
        Assert.Equal(verifierDid, body.RootElement.GetProperty("verifierDid").GetString());
        Assert.Equal(Audience, body.RootElement.GetProperty("audience").GetString());
        Assert.Equal(issuerDid, body.RootElement.GetProperty("trustedIssuerDid").GetString());

        Assert.True(OfflineSignedPresentationRequest.TryRead(
            requestJwt, verifierDid, Audience, TimeProvider.System, out var challenge));
        Assert.NotNull(challenge);
        Assert.Equal(body.RootElement.GetProperty("nonce").GetString(), challenge.Nonce);
        Assert.Equal(issuerDid, challenge.TrustedIssuerDid);
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            requestJwt, holderDid, Audience, TimeProvider.System, out _));
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            requestJwt, verifierDid, "https://wrong.example/receive", TimeProvider.System, out _));

        string[] parts = requestJwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(requestJwt).Replace(
                Audience, "https://forged.example/receive", StringComparison.Ordinal));
        Assert.False(OfflineSignedPresentationRequest.TryRead(
            string.Join('.', parts), verifierDid, Audience, TimeProvider.System, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string originalCredential = Vcdm20JoseCredential.Create(
            issuerDid, holderDid, "MembershipCredential", Vocabulary, subject.RootElement,
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1), now.AddMinutes(10));
        string presentation = Vcdm20JosePresentation.Create(
            requestJwt, verifierDid, Audience, originalCredential, "MembershipCredential",
            Vocabulary, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        using var holderPayload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(presentation));
        Assert.Equal(holderDid, holderPayload.RootElement.GetProperty("holder").GetString());
        Assert.Equal(challenge.Nonce, holderPayload.RootElement.GetProperty("nonce").GetString());
        Assert.Equal(Audience, holderPayload.RootElement.GetProperty("aud").GetString());
        Assert.Equal(originalCredential,
            holderPayload.RootElement.GetProperty("verifiableCredential")[0]
                .GetProperty("id").GetString()!["data:application/vc+jwt,".Length..]);
    }

    [Fact]
    public async Task AnonymousWrongScopeAndUnownedVerifierCannotSign()
    {
        using var outsideKey = NewKey();
        string outsideDid = DidFromKey(outsideKey);
        var request = new { verifierDid = outsideDid, audience = Audience,
            trustedIssuerDid = outsideDid, lifetimeSeconds = 120 };
        using var anonymous = await _client.PostAsJsonAsync(Route, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issueOnly = await GetTokenAsync("credential:issue").ConfigureAwait(true);
        using var forbidden = await PostAsync(Route, request, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string verifyOnly = await GetTokenAsync("credential:verify").ConfigureAwait(true);
        using var unowned = await PostAsync(Route, request, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unowned.StatusCode);
    }

    [Fact]
    public async Task RejectsUntrustedAudienceIssuerAndUnboundedLifetime()
    {
        string token = await GetTokenAsync("did:manage credential:verify").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        foreach (var request in new[]
        {
            new { verifierDid, audience = "http://verifier.example/insecure", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = "did:key:invalid", lifetimeSeconds = 120 },
            new { verifierDid, audience = Audience, trustedIssuerDid = issuerDid, lifetimeSeconds = 301 },
            new { verifierDid, audience = Audience + "#fragment", trustedIssuerDid = issuerDid, lifetimeSeconds = 120 }
        })
        {
            using var invalid = await PostAsync(Route, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        }
    }

    private async Task<string> CreateDidAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Create verifier DID", "did").ConfigureAwait(true);
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

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
