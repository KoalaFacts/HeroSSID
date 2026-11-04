using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Authenticated HTTP issuance to a holder not enrolled in HeroSSID. This proves
/// issuer signature and tenant-owned signing, not wallet interoperability or holder control.
/// </summary>
public sealed class JwtVcJsonCredentialIssuanceHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private const string Endpoint = "/api/v1/credentials/jwt-vc-json/issue";
    private const string StatusEndpoint = "/api/v1/credentials/jwt-vc-json/sign-revocation-snapshot";
    private static readonly string[] SeparateRequiredScopes = ["credential:revoke", "did:manage"];
    private static readonly string[] ForgedStatusTokens = ["not-a-valid-issued-jwt"];

    [Fact]
    public async Task AuthenticatedIssuerSignsVc11JwtForUnenrolledHolder()
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var response = await PostAsync(Endpoint,
            Request(issuerDid, holderDid, holderDid, DateTimeOffset.UtcNow.AddMinutes(5)), token)
            .ConfigureAwait(true);
        string credential = await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Issue issuer-signed VC1.1 JWT", "credential").ConfigureAwait(true);

        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(credential));
        // Existing clients do not opt in to fractional NumericDate values.
        Assert.True(payload.RootElement.GetProperty("nbf").TryGetInt64(out _));
        Assert.True(payload.RootElement.GetProperty("exp").TryGetInt64(out _));
        var vc = payload.RootElement.GetProperty("vc");
        Assert.Equal("https://www.w3.org/2018/credentials/v1", vc.GetProperty("@context")[0].GetString());
        Assert.Equal(CredentialType, vc.GetProperty("type")[1].GetString());
        Assert.False(vc.TryGetProperty("context", out _));
        Assert.True(JwtVcJsonCredential.TryVerify(credential, issuerDid, holderDid,
            CredentialType, Vocabulary, DateTimeOffset.UtcNow, out var subject));
        Assert.Equal(holderDid, subject.GetProperty("id").GetString());
        Assert.Equal("active", subject.GetProperty("membership").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticatedHttpIssuerCanSignStandardSubOnlySubject(bool includeJti)
    {
        // Exercise the authenticated tenant-owned HTTP entry point, not merely
        // the library issuer. A remote holder is not enrolled in HeroSSID.
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        const string credentialId = "https://issuer.example/credentials/http-sub-only";

        using var issued = await PostAsync(Endpoint, new
        {
            issuerDid,
            holderDid,
            credentialType = CredentialType,
            subjectContextUri = Vocabulary,
            credentialSubject = new { membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5),
            credentialId = includeJti ? credentialId : null
        }, token).ConfigureAwait(true);
        string jwt = await SetupResponse.ReadRequiredStringAsync(
            issued, HttpStatusCode.Created, "Issue sub-only VC1.1 JWT",
            "credential").ConfigureAwait(true);

        using var signed = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal(holderDid, signed.RootElement.GetProperty("sub").GetString());
        Assert.False(signed.RootElement.GetProperty("vc")
            .GetProperty("credentialSubject").TryGetProperty("id", out _));
        Assert.Equal(includeJti, signed.RootElement.TryGetProperty("jti", out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, DateTimeOffset.UtcNow,
            out var claims, out string? signedId));
        Assert.False(claims.TryGetProperty("id", out _));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(includeJti ? credentialId : null, signedId);

        using var other = Key.Create(SignatureAlgorithm.Ed25519);
        string otherDid = DidFromKey(other.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuerDid, otherDid,
            CredentialType, Vocabulary, DateTimeOffset.UtcNow, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HttpIssuerOptInRetainsExactSignedValidityWithoutBackdating(bool includeJti)
    {
        // The existing HTTP route rounds nbf back to the whole second and exp
        // down. Remote callers need an explicit, wire-level opt-in to preserve
        // the requested 100ns expiry without making a credential valid early.
        string token = await GetTokenAsync("did:manage credential:issue")
            .ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        DateTimeOffset validUntil = DateTimeOffset.UtcNow.AddMinutes(5).AddTicks(123_4567);
        DateTimeOffset beforeRequest = DateTimeOffset.UtcNow;
        using var response = await PostAsync(Endpoint, new
        {
            issuerDid,
            holderDid,
            credentialType = CredentialType,
            subjectContextUri = Vocabulary,
            credentialSubject = new { membership = "active" },
            validUntil,
            credentialId = includeJti ? "https://issuer.example/credentials/http-exact" : null,
            exactValidity = true
        }, token).ConfigureAwait(true);
        DateTimeOffset afterResponse = DateTimeOffset.UtcNow;
        string jwt = await SetupResponse.ReadRequiredStringAsync(
            response, HttpStatusCode.Created, "Issue exact-validity HTTP VC1.1 JWT",
            "credential").ConfigureAwait(true);

        using var signed = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        JsonElement payload = signed.RootElement;
        decimal expiresAt = (decimal)(validUntil.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks)
            / TimeSpan.TicksPerSecond;
        decimal signedStart = payload.GetProperty("nbf").GetDecimal();
        decimal requestStart = (decimal)(beforeRequest.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks)
            / TimeSpan.TicksPerSecond;
        decimal responseEnd = (decimal)(afterResponse.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks)
            / TimeSpan.TicksPerSecond;

        Assert.Equal(expiresAt, payload.GetProperty("exp").GetDecimal());
        Assert.Equal(signedStart, payload.GetProperty("iat").GetDecimal());
        Assert.InRange(signedStart, requestStart, responseEnd);
        Assert.Equal(includeJti, payload.TryGetProperty("jti", out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, beforeRequest.AddSeconds(-1), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, afterResponse, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, validUntil.AddTicks(-1), out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, validUntil, out _));
    }

    [Fact]
    public async Task AuthenticatedHttpIssueAndVerifyReleaseOnlyAuthenticSignedCredentialIdentifier()
    {
        string token = await GetTokenAsync("did:manage credential:issue credential:verify credential:revoke")
            .ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        const string credentialId = "https://issuer.example/credentials/member-123";

        using var issued = await PostAsync(Endpoint, new
        {
            issuerDid,
            holderDid,
            credentialType = CredentialType,
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5),
            credentialId
        }, token).ConfigureAwait(true);
        string jwt = await SetupResponse.ReadRequiredStringAsync(
            issued, HttpStatusCode.Created, "Issue credential with signed identifier",
            "credential").ConfigureAwait(true);

        using var payload = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal(credentialId, payload.RootElement.GetProperty("jti").GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, issuerDid, holderDid,
            CredentialType, Vocabulary, DateTimeOffset.UtcNow, out var verifiedSubject,
            out string? verifiedId));
        Assert.Equal("active", verifiedSubject.GetProperty("membership").GetString());
        Assert.Equal(credentialId, verifiedId);

        var verifierPolicy = new
        {
            credential = jwt,
            trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid,
            expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary
        };
        using var verified = await PostAsync("/api/v1/credentials/jwt-vc-json/verify",
            verifierPolicy, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        JsonElement body = await verified.Content.ReadFromJsonAsync<JsonElement>()
            .ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
        Assert.Equal(credentialId, body.GetProperty("verifiedCredentialId").GetString());

        using var exported = await PostAsync(StatusEndpoint, new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = new[] { jwt }
        }, token).ConfigureAwait(true);
        string snapshot = await SetupResponse.ReadRequiredStringAsync(
            exported, HttpStatusCode.Created, "Export signed revoked status",
            "snapshotJwt").ConfigureAwait(true);
        using var revoked = await PostAsync("/api/v1/credentials/jwt-vc-json/verify-with-status",
            new
            {
                verifierPolicy.credential,
                verifierPolicy.trustedIssuerDid,
                verifierPolicy.expectedHolderDid,
                verifierPolicy.expectedCredentialType,
                verifierPolicy.subjectContextUri,
                revocationSnapshot = snapshot
            }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        JsonElement revokedBody = await revoked.Content.ReadFromJsonAsync<JsonElement>()
            .ConfigureAwait(true);
        Assert.Equal("Revoked", revokedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedSubject").ValueKind);
        Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedCredentialId").ValueKind);
    }

    [Theory]
    [InlineData("http://issuer.example/credentials/insecure")]
    [InlineData("https://user:pass@issuer.example/credentials/secret")]
    public async Task AuthenticatedHttpIssuerRejectsUnsafeCredentialIdentifiers(string credentialId)
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var issued = await PostAsync(Endpoint, new
        {
            issuerDid,
            holderDid,
            credentialType = CredentialType,
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5),
            credentialId
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, issued.StatusCode);
    }

    [Fact]
    public async Task AnonymousAndVerifyOnlyClientsCannotIssueAndMissingIssuerCannotSign()
    {
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var body = Request("did:key:zUnknown", holderDid, holderDid, DateTimeOffset.UtcNow.AddMinutes(5));

        using var anonymous = await _client.PostAsJsonAsync(Endpoint, body).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string verifyOnly = await GetTokenAsync("credential:verify").ConfigureAwait(true);
        using var forbidden = await PostAsync(Endpoint, body, verifyOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string issueOnly = await GetTokenAsync("credential:issue").ConfigureAwait(true);
        using var missing = await PostAsync(Endpoint, body, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task IssuerRejectsUnmatchedSubjectAndUnboundedValidity()
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var mismatch = await PostAsync(Endpoint,
            Request(issuerDid, holderDid, issuerDid, DateTimeOffset.UtcNow.AddMinutes(5)), token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);

        using var tooLong = await PostAsync(Endpoint,
            Request(issuerDid, holderDid, holderDid, DateTimeOffset.UtcNow.AddDays(1)), token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
    }

    [Fact]
    public async Task UnsupportedDcqlTypeTermCannotBeMisissuedAsExpandedIri()
    {
        string token = await GetTokenAsync("did:manage credential:issue").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var result = await PostAsync(Endpoint, new
        {
            issuerDid,
            holderDid,
            credentialType = "MembershipCredential",
            subjectContextUri = Vocabulary,
            credentialSubject = new { id = holderDid, membership = "active" },
            validUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
    }


    [Fact]
    public async Task OwnedIssuerCanExportSignedVc11RevocationStatusForExternalVerifier()
    {
        string token = await GetTokenAsync("did:manage credential:issue credential:revoke").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var holder = Key.Create(SignatureAlgorithm.Ed25519);
        string holderDid = DidFromKey(holder.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var issuance = await PostAsync(Endpoint,
            Request(issuerDid, holderDid, holderDid, DateTimeOffset.UtcNow.AddMinutes(5)), token)
            .ConfigureAwait(true);
        string credential = await SetupResponse.ReadRequiredStringAsync(
            issuance, HttpStatusCode.Created, "Issue VC1.1 before status export", "credential")
            .ConfigureAwait(true);

        using var export = await PostAsync(StatusEndpoint, new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = new[] { credential }
        }, token).ConfigureAwait(true);
        string snapshot = await SetupResponse.ReadRequiredStringAsync(
            export, HttpStatusCode.Created, "Export issuer-signed VC1.1 revocation status",
            "snapshotJwt").ConfigureAwait(true);

        Assert.Equal("Revoked", JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
            issuerDid, DateTimeOffset.UtcNow).ToString());
        Assert.Equal("Invalid", JwtVcJsonRevocationSnapshot.Check(snapshot, credential,
            issuerDid, DateTimeOffset.UtcNow.AddMinutes(2)).ToString());

        using var empty = await PostAsync(StatusEndpoint, new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Array.Empty<string>()
        }, token).ConfigureAwait(true);
        string notListed = await SetupResponse.ReadRequiredStringAsync(
            empty, HttpStatusCode.Created, "Sign caller-supplied empty VC1.1 status set",
            "snapshotJwt").ConfigureAwait(true);
        Assert.Equal("NotListed", JwtVcJsonRevocationSnapshot.Check(notListed, credential,
            issuerDid, DateTimeOffset.UtcNow).ToString());
    }

    [Fact]
    public async Task StatusExportRequiresIndependentRevocationAndDidManagementScopes()
    {
        string fullToken = await GetTokenAsync("did:manage credential:revoke").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(fullToken).ConfigureAwait(true);
        var request = new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Array.Empty<string>()
        };

        using var anonymous = await _client.PostAsJsonAsync(StatusEndpoint, request)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        foreach (string scope in SeparateRequiredScopes)
        {
            string partialToken = await GetTokenAsync(scope).ConfigureAwait(true);
            using var forbidden = await PostAsync(StatusEndpoint, request, partialToken)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        using var allowed = await PostAsync(StatusEndpoint, request, fullToken)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
    }

    [Fact]
    public async Task StatusExportRejectsInvalidForeignAndStaleObservationWithoutSigning()
    {
        string token = await GetTokenAsync("did:manage credential:revoke").ConfigureAwait(true);
        string issuerDid = await CreateDidAsync(token).ConfigureAwait(true);
        using var foreignKey = Key.Create(SignatureAlgorithm.Ed25519);
        string foreignDid = DidFromKey(foreignKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        using var foreign = await PostAsync(StatusEndpoint, new
        {
            issuerDid = foreignDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = Array.Empty<string>()
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

        using var forged = await PostAsync(StatusEndpoint, new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow,
            revokedCredentials = ForgedStatusTokens
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);

        using var stale = await PostAsync(StatusEndpoint, new
        {
            issuerDid,
            observedAt = DateTimeOffset.UtcNow.AddMinutes(-2),
            revokedCredentials = Array.Empty<string>()
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
    }

    private static object Request(string issuer, string holder, string subject,
        DateTimeOffset expiry) => new
    {
        issuerDid = issuer,
        holderDid = holder,
        credentialType = CredentialType,
        subjectContextUri = Vocabulary,
        credentialSubject = new { id = subject, membership = "active" },
        validUntil = expiry
    };

    private async Task<string> CreateDidAsync(string token)
    {
        using var response = await PostAsync("/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await SetupResponse.ReadRequiredStringAsync(response, HttpStatusCode.Created,
            "Create issuer DID", "did").ConfigureAwait(true);
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
        return await SetupResponse.ReadRequiredStringAsync(response, HttpStatusCode.OK,
            "Obtain scoped token", "access_token").ConfigureAwait(true);
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
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
