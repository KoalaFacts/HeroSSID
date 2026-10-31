using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Real HTTP and isolated PostgreSQL boundary for a tenant-owned VC2 status
/// export. The issuer supplies its own observed complete revocation set;
/// successful signing does not establish completeness or live status.
/// </summary>
public sealed class Vcdm20IssuerStatusExportHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string Path = "/api/v1/credentials/vcdm20/sign-revocation-snapshot";
    private const string VerifyPath = "/api/v1/credentials/vcdm20/verify-with-status";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task OwnedIssuerSignsAuthenticVc2RevocationAndVerifierDoesNotReleaseRevokedClaims()
    {
        string token = await GetTokenAsync(
            "did:manage credential:issue credential:revoke credential:verify").ConfigureAwait(true);
        string issuer = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        string revokedJwt = await IssueAsync(issuer, holderDid, "revoked", token).ConfigureAwait(true);
        string cleanJwt = await IssueAsync(issuer, holderDid, "active", token).ConfigureAwait(true);

        using var export = await PostAsync(Path, new
        {
            issuerDid = issuer,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = new[] { revokedJwt }
        }, token).ConfigureAwait(true);
        string snapshot = await SetupResponse.ReadRequiredStringAsync(
            export, HttpStatusCode.Created, "Sign VC2 status", "snapshotJwt").ConfigureAwait(true);

        Assert.Equal(Vcdm20RevocationCheckResult.Revoked,
            Vcdm20RevocationSnapshot.Check(snapshot, revokedJwt, issuer, DateTimeOffset.UtcNow));
        Assert.Equal(Vcdm20RevocationCheckResult.SignedNotListed,
            Vcdm20RevocationSnapshot.Check(snapshot, cleanJwt, issuer, DateTimeOffset.UtcNow));

        using var denied = await PostAsync(VerifyPath,
            VerifyRequest(revokedJwt, issuer, holderDid, snapshot), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedBody = await denied.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Revoked", deniedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedBody.GetProperty("verifiedSubject").ValueKind);

        using var admitted = await PostAsync(VerifyPath,
            VerifyRequest(cleanJwt, issuer, holderDid, snapshot), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);
        var admittedBody = await admitted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", admittedBody.GetProperty("status").GetString());
        Assert.Equal("active", admittedBody.GetProperty("verifiedSubject").GetProperty("membership").GetString());
    }

    [Fact]
    public async Task BothIssuerRevocationAndDidManagementScopesAreRequired()
    {
        object request = new
        {
            issuerDid = "did:key:zUnknown",
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Array.Empty<string>()
        };

        using var anonymous = await _client.PostAsJsonAsync(Path, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        foreach (string scope in new[] { "credential:verify", "credential:revoke", "did:manage" })
        {
            string token = await GetTokenAsync(scope).ConfigureAwait(true);
            using var forbidden = await PostAsync(Path, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        string allowed = await GetTokenAsync("credential:revoke did:manage").ConfigureAwait(true);
        using var unknownIssuer = await PostAsync(Path, request, allowed).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, unknownIssuer.StatusCode);
    }

    [Fact]
    public async Task ForeignIssuerForgedCredentialAndStaleObservationFailWithoutSigning()
    {
        string token = await GetTokenAsync(
            "did:manage credential:issue credential:revoke").ConfigureAwait(true);
        string issuer = await CreateDidAsync(token).ConfigureAwait(true);
        string foreignIssuer = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        string credential = await IssueAsync(issuer, holderDid, "member", token).ConfigureAwait(true);

        using var foreign = await PostAsync(Path, new
        {
            issuerDid = foreignIssuer,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = new[] { credential }
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, foreign.StatusCode);

        string[] segments = credential.Split('.');
        segments[1] = segments[1][..^1] + (segments[1][^1] == 'A' ? "B" : "A");
        using var forged = await PostAsync(Path, new
        {
            issuerDid = issuer,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = new[] { string.Join('.', segments) }
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);

        using var stale = await PostAsync(Path, new
        {
            issuerDid = issuer,
            observedAt = DateTimeOffset.UtcNow.AddMinutes(-2),
            revokedCredentials = new[] { credential }
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
    }

    [Fact]
    public async Task UnknownIssuerAndOversizedStatusSetCannotExport()
    {
        string token = await GetTokenAsync("credential:revoke did:manage").ConfigureAwait(true);
        using var missing = await PostAsync(Path, new
        {
            issuerDid = "did:key:z6Mkunknown",
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Array.Empty<string>()
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        using var tooMany = await PostAsync(Path, new
        {
            issuerDid = "did:key:z6Mkunknown",
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Enumerable.Repeat("not-a-credential", 257).ToArray()
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, tooMany.StatusCode);
    }

    private async Task<string> IssueAsync(string issuerDid, string holderDid,
        string membership, string token)
    {
        using var response = await PostAsync("/api/v1/credentials/vcdm20/issue", new
        {
            issuerDid,
            holderDid,
            credentialType = "MembershipCredential",
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Issue direct VC2", "credential").ConfigureAwait(true);
    }

    private static object VerifyRequest(string credential, string issuerDid, string holderDid,
        string snapshot) => new
        {
            credential,
            trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid,
            expectedCredentialType = "MembershipCredential",
            subjectContextUri = Vocabulary,
            revocationSnapshot = snapshot
        };

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

    private static string DidFromKey(byte[] publicKey)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        publicKey.CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
