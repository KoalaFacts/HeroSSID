using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Real HTTP and disposable PostgreSQL contract: an independently pinned issuer
/// must authenticate both the VC2 JWT and a separate issuer-signed status proof.
/// A bare valid VC2 signature is insufficient for a status-checked response.
/// </summary>
public sealed class Vcdm20CredentialStatusVerificationHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string Path = "/api/v1/credentials/vcdm20/verify-with-status";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task SignedNotListedReleasesClaimsButAuthenticRevocationDoesNot()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        var now = TimeProvider.System.GetUtcNow();
        string cleanStatus = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), now, TimeProvider.System);
        string revokedStatus = Vcdm20RevocationSnapshot.Create(
            issuerDid, [credential], Seed(issuer), now, TimeProvider.System);

        using var clean = await _client.AuthorizedPostAsJsonAsync(Path,
            Request(credential, issuerDid, holderDid, cleanStatus)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, clean.StatusCode);
        var valid = await clean.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", valid.GetProperty("status").GetString());
        Assert.Equal("member", valid.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var revoked = await _client.AuthorizedPostAsJsonAsync(Path,
            Request(credential, issuerDid, holderDid, revokedStatus)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var invalid = await revoked.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Revoked", invalid.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task ForeignSnapshotTamperedJwtAndWrongIssuerOrVocabularyFailWithoutClaims()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var foreign = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string foreignDid = Did(foreign);
        string credential = Issue(issuer, issuerDid, holderDid);
        var now = TimeProvider.System.GetUtcNow();
        string status = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), now, TimeProvider.System);
        string foreignStatus = Vcdm20RevocationSnapshot.Create(
            foreignDid, [], Seed(foreign), now, TimeProvider.System);
        string[] parts = credential.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(credential).Replace("member", "admin",
                StringComparison.Ordinal));
        string tampered = string.Join('.', parts);

        var attempts = new[]
        {
            Request(credential, issuerDid, holderDid, foreignStatus),
            Request(tampered, issuerDid, holderDid, status),
            Request(credential, foreignDid, holderDid, status),
            Request(credential, issuerDid, foreignDid, status),
            new
            {
                Credential = credential,
                TrustedIssuerDid = issuerDid,
                ExpectedHolderDid = holderDid,
                ExpectedCredentialType = "DifferentCredential",
                SubjectContextUri = Context,
                RevocationSnapshot = status
            }
        };
        foreach (var request in attempts)
        {
            using var rejected = await _client.AuthorizedPostAsJsonAsync(Path, request).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
            var result = await rejected.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("Invalid", result.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, result.GetProperty("verifiedSubject").ValueKind);
        }
    }

    [Fact]
    public async Task AnonymousAndWrongScopeCannotCheckStatus()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        string status = Vcdm20RevocationSnapshot.Create(issuerDid, [], Seed(issuer),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);
        var request = Request(credential, issuerDid, holderDid, status);

        using var anonymous = await _client.PostAsJsonAsync(Path, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issueOnly = await ScopeTokenAsync("credential:issue").ConfigureAwait(true);
        using var denied = await PostWithBearerAsync(request, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        string verifyOnly = await ScopeTokenAsync("credential:verify").ConfigureAwait(true);
        using var accepted = await PostWithBearerAsync(request, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
    }

    [Fact]
    public async Task MissingStatusAndUnboundedStatusAreBadRequests()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        foreach (string snapshot in new[] { "", new string('a', 65_537) })
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(
                Path, Request(credential, issuerDid, holderDid, snapshot)).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task VerifierCutoffRejectsAuthenticPreIncidentCleanStatusWithoutClaims()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string oldSnapshot = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), now.AddSeconds(-25), TimeProvider.System);

        // The snapshot is genuinely signed and would pass the legacy check.
        using var legacy = await _client.AuthorizedPostAsJsonAsync(Path,
            Request(credential, issuerDid, holderDid, oldSnapshot)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, legacy.StatusCode);
        var oldResult = await legacy.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", oldResult.GetProperty("status").GetString());

        using var rejected = await _client.AuthorizedPostAsJsonAsync(Path,
            CutoffRequest(credential, issuerDid, holderDid, oldSnapshot,
                now.AddSeconds(-10))).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        var result = await rejected.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", result.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task VerifierCutoffAcceptsFreshStatusButRejectsFuturePolicy()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string current = Vcdm20RevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), now, TimeProvider.System);
        using var fresh = await _client.AuthorizedPostAsJsonAsync(Path,
            CutoffRequest(credential, issuerDid, holderDid, current,
                now.AddSeconds(-10))).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        var accepted = await fresh.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", accepted.GetProperty("status").GetString());

        using var future = await _client.AuthorizedPostAsJsonAsync(Path,
            CutoffRequest(credential, issuerDid, holderDid, current,
                now.AddMinutes(2))).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, future.StatusCode);
    }

    private static object CutoffRequest(string credential, string issuerDid,
        string holderDid, string snapshot, DateTimeOffset minimumObservedAt) =>
        new
        {
            Credential = credential,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = CredentialType,
            SubjectContextUri = Context,
            RevocationSnapshot = snapshot,
            MinimumStatusObservedAt = minimumObservedAt
        };

    private static object Request(string credential, string issuerDid, string holderDid, string snapshot) =>
        new
        {
            Credential = credential,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = CredentialType,
            SubjectContextUri = Context,
            RevocationSnapshot = snapshot
        };

    private static string Issue(Key issuer, string issuerDid, string holderDid)
    {
        var now = TimeProvider.System.GetUtcNow();
        return Vcdm20JoseCredential.Create(issuerDid, holderDid, CredentialType,
            Context, JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            Seed(issuer), now.AddMinutes(-1), now.AddMinutes(5));
    }

    private async Task<string> ScopeTokenAsync(string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await _client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(response, HttpStatusCode.OK,
            "Obtain scoped verification token", "access_token").ConfigureAwait(true);
    }

    private async Task<HttpResponseMessage> PostWithBearerAsync(object payload, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = JsonContent.Create(payload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(request).ConfigureAwait(true);
    }

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static byte[] Seed(Key key) => key.Export(KeyBlobFormat.RawPrivateKey);

    private static string Did(Key key)
    {
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
