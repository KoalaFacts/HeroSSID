using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Tenant-owned issuer HTTP recipient signing, not proof of Wallet interoperability,
/// holder possession, real identity, consent or business authorization.
/// </summary>
public sealed class JwtVcJsonAudienceIssuanceHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string IssuePath = "/api/v1/credentials/jwt-vc-json/issue-for-audience";
    private const string LegacyIssuePath = "/api/v1/credentials/jwt-vc-json/issue";
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify-for-audience";
    private const string Type = "https://issuer.example/credentials#Membership";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/credentials");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task TenantIssuerSignsRecipientBoundJwtConsumableByIndependentHttpVerifier()
    {
        string token = await TokenAsync("did:manage credential:issue credential:verify").ConfigureAwait(true);
        string issuerDid = await RegisterIssuerAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = Did(holder);
        using var issued = await PostAsync(IssuePath,
            Request(issuerDid, holderDid, Recipient), token).ConfigureAwait(true);
        string jwt = await SetupResponse.ReadRequiredStringAsync(issued,
            HttpStatusCode.Created, "Issue recipient-bound VC1.1 JWT", "credential")
            .ConfigureAwait(true);

        Assert.True(JwtVcJsonCredential.TryVerifyForAudience(jwt, issuerDid,
            holderDid, Type, Context, Recipient, DateTimeOffset.UtcNow, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            Type, Context, DateTimeOffset.UtcNow, out _));

        var policy = new
        {
            credential = jwt,
            trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid,
            expectedCredentialType = Type,
            subjectContextUri = Context,
            expectedAudience = Recipient
        };
        using var accepted = await PostAsync(VerifyPath, policy, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var good = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", good.GetProperty("status").GetString());
        Assert.Equal("active", good.GetProperty("verifiedSubject")
            .GetProperty("membership").GetString());

        using var rejected = await PostAsync(VerifyPath, new
        {
            policy.credential, policy.trustedIssuerDid, policy.expectedHolderDid,
            policy.expectedCredentialType, policy.subjectContextUri,
            expectedAudience = new Uri("https://attacker.example/credentials")
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        var wrong = await rejected.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", wrong.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, wrong.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task LegacyIssueDoesNotSilentlyIgnoreRecipientPolicyAndOptInRejectsInvalidRecipient()
    {
        string token = await TokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await RegisterIssuerAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = Did(holder);

        using var ignored = await PostAsync(LegacyIssuePath,
            Request(issuerDid, holderDid, Recipient), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, ignored.StatusCode);

        using var omitted = await PostAsync(IssuePath,
            Request(issuerDid, holderDid, null), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, omitted.StatusCode);

        using var http = await PostAsync(IssuePath,
            Request(issuerDid, holderDid, new Uri("http://verifier.example/credentials")),
            token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, http.StatusCode);
    }

    [Fact]
    public async Task AudienceIssuanceRequiresAuthenticatedIssuanceScopeAndTenantOwnedKey()
    {
        string token = await TokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await RegisterIssuerAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = Did(holder);
        var body = Request(issuerDid, holderDid, Recipient);

        using var anonymous = await _client.PostAsJsonAsync(IssuePath, body)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyToken = await TokenAsync("credential:verify").ConfigureAwait(true);
        using var forbidden = await PostAsync(IssuePath, body, verifyToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        using var missing = await PostAsync(IssuePath,
            Request("did:key:zUnknown", holderDid, Recipient), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task RecipientRouteSignsOptionalMetadataAndExactValidityInSameOriginalJwt()
    {
        string token = await TokenAsync("did:manage credential:issue credential:verify")
            .ConfigureAwait(true);
        string issuerDid = await RegisterIssuerAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = Did(holder);
        var credentialId = new Uri("https://issuer.example/credentials/recipient-42");
        const string issuerName = "Issuer display name (not verified legal identity)";
        DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(4).AddTicks(37);

        var body = new
        {
            issuerDid,
            holderDid,
            credentialType = Type,
            subjectContextUri = Context,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = expiry,
            recipientAudience = Recipient,
            credentialId,
            issuerName,
            exactValidity = true
        };
        using var issued = await PostAsync(IssuePath, body, token).ConfigureAwait(true);
        string jwt = await SetupResponse.ReadRequiredStringAsync(issued,
            HttpStatusCode.Created, "Issue aud+jti+issuer.name+fractional validity", "credential")
            .ConfigureAwait(true);

        Assert.True(JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
            jwt, issuerDid, holderDid, Type, Context, Recipient,
            DateTimeOffset.UtcNow, out var subject, out string? signedId,
            out string? signedName, out DateTimeOffset? issuedAt,
            out DateTimeOffset? expiresAt));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.Equal(credentialId.AbsoluteUri, signedId);
        Assert.Equal(issuerName, signedName);
        Assert.NotNull(issuedAt);
        Assert.Equal(expiry, expiresAt);

        // A signature and metadata cannot bypass independently configured recipient trust.
        Assert.False(JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
            jwt, issuerDid, holderDid, Type, Context,
            new Uri("https://attacker.example/credentials"),
            DateTimeOffset.UtcNow, out var wrongSubject, out var wrongId,
            out var wrongName, out var wrongStart, out var wrongEnd));
        Assert.Equal(JsonValueKind.Undefined, wrongSubject.ValueKind);
        Assert.Null(wrongId);
        Assert.Null(wrongName);
        Assert.Null(wrongStart);
        Assert.Null(wrongEnd);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            Type, Context, DateTimeOffset.UtcNow, out _));

        // The existing route must not silently drop a requested audience even
        // when other valid signed metadata is present.
        using var oldRoute = await PostAsync(LegacyIssuePath, body, token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, oldRoute.StatusCode);
    }

    private static object Request(string issuer, string holder, Uri? audience) => new
    {
        issuerDid = issuer,
        holderDid = holder,
        credentialType = Type,
        subjectContextUri = Context,
        credentialSubject = new { id = holder, membership = "active" },
        validUntil = DateTimeOffset.UtcNow.AddMinutes(5),
        recipientAudience = audience
    };

    private async Task<string> RegisterIssuerAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids", new
        {
            method = "did:key",
            keyType = "Ed25519"
        }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(response,
            HttpStatusCode.Created, "Create issuer DID", "did").ConfigureAwait(true);
    }

    private async Task<string> TokenAsync(string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await _client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(response,
            HttpStatusCode.OK, "Obtain scoped token", "access_token").ConfigureAwait(true);
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

    private static string Did(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
