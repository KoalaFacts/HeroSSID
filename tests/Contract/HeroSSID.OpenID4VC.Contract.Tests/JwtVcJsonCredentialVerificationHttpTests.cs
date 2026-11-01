using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Real HTTP/PostgreSQL contract for independently pinned VC1.1 jwt_vc_json
/// issuer verification, with optional private issuer-signed status checking.
/// A JWT signature alone never establishes holder control or business authority.
/// </summary>
public sealed class JwtVcJsonCredentialVerificationHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify";
    private const string StatusPath = "/api/v1/credentials/jwt-vc-json/verify-with-status";
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task ExternalVerifierAuthenticatesIssuerSignatureAndReleasesOnlyVerifiedVc11Subject()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);

        using var verified = await _client.AuthorizedPostAsJsonAsync(VerifyPath,
            Request(credential, issuerDid, holderDid)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var response = await verified.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", response.GetProperty("status").GetString());
        Assert.Equal("member", response.GetProperty("verifiedSubject").GetProperty("role").GetString());
        Assert.Equal(holderDid, response.GetProperty("verifiedSubject").GetProperty("id").GetString());
    }

    [Fact]
    public async Task IssuerSignedStatusDistinguishesNotListedRevokedAndForeignWithoutLeakingClaims()
    {
        using var issuer = NewKey();
        using var foreign = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        DateTimeOffset observed = TimeProvider.System.GetUtcNow();
        string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [], Seed(issuer),
            observed, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [credential],
            Seed(issuer), observed, TimeProvider.System);
        string foreignStatus = JwtVcJsonRevocationSnapshot.Create(Did(foreign), [],
            Seed(foreign), observed, TimeProvider.System);

        using var accepted = await _client.AuthorizedPostAsJsonAsync(StatusPath,
            RequestWithStatus(credential, issuerDid, holderDid, clean)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var acceptedBody = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", acceptedBody.GetProperty("status").GetString());
        Assert.Equal("member", acceptedBody.GetProperty("verifiedSubject").GetProperty("role").GetString());

        foreach (var attempt in new[]
        {
            (Status: revoked, Expected: "Revoked"),
            (Status: foreignStatus, Expected: "Invalid")
        })
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(StatusPath,
                RequestWithStatus(credential, issuerDid, holderDid, attempt.Status)).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal(attempt.Expected, body.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
        }
    }

    [Fact]
    public async Task AuthenticatedHttpRejectsAuthenticPreIncidentStatusAndHonorsNewIssuerObservation()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string original = Issue(issuer, issuerDid, holderDid);
        DateTimeOffset observed = TimeProvider.System.GetUtcNow().AddSeconds(-25);
        DateTimeOffset cutoff = observed.AddSeconds(10);
        string stale = JwtVcJsonRevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), observed, TimeProvider.System);

        using var baseline = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
        {
            credential = original, trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary,
            revocationSnapshot = stale
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, baseline.StatusCode);
        var baselineBody = await baseline.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", baselineBody.GetProperty("status").GetString());

        using var denied = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
        {
            credential = original, trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary,
            revocationSnapshot = stale, minimumStatusObservedAt = cutoff
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedBody = await denied.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", deniedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedBody.GetProperty("verifiedSubject").ValueKind);

        DateTimeOffset renewedAt = TimeProvider.System.GetUtcNow();
        string renewed = JwtVcJsonRevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), renewedAt, TimeProvider.System);
        using var accepted = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
        {
            credential = original, trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary,
            revocationSnapshot = renewed, minimumStatusObservedAt = cutoff
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var acceptedBody = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedNotListed", acceptedBody.GetProperty("status").GetString());
        Assert.Equal("member", acceptedBody.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var notIgnored = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential = original, trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary, minimumStatusObservedAt = cutoff
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, notIgnored.StatusCode);
    }

    [Fact]
    public async Task ForgedIssuerJwtAndWrongIssuerHolderTypeOrVocabularyFailClosed()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var foreign = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        string[] parts = credential.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(credential).Replace("member", "admin",
                StringComparison.Ordinal));
        string forged = string.Join('.', parts);
        var attempts = new[]
        {
            Request(forged, issuerDid, holderDid),
            Request(credential, Did(foreign), holderDid),
            Request(credential, issuerDid, Did(foreign)),
            Request(credential, issuerDid, holderDid,
                "https://issuer.example/credentials#AdministratorCredential"),
            Request(credential, issuerDid, holderDid, context: new Uri("https://attacker.example/contexts/v1"))
        };

        foreach (var attempt in attempts)
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(VerifyPath, attempt)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("Invalid", body.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
        }
    }

    [Fact]
    public async Task BothRoutesRequireVerificationScopeAndRejectMissingStatus()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        var request = Request(credential, issuerDid, holderDid);

        using var anonymous = await _client.PostAsJsonAsync(VerifyPath, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issueOnly = await ScopeTokenAsync("credential:issue").ConfigureAwait(true);
        using var forbidden = await PostWithBearerAsync(VerifyPath, request, issueOnly)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string verifyOnly = await ScopeTokenAsync("credential:verify").ConfigureAwait(true);
        using var verified = await PostWithBearerAsync(VerifyPath, request, verifyOnly)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);

        using var missing = await _client.AuthorizedPostAsJsonAsync(StatusPath,
            RequestWithStatus(credential, issuerDid, holderDid, "")).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
    }

    [Fact]
    public async Task HistoricalAndCurrentVc11IssuersAuthenticateOverRealHttpWithSameSignerStatus()
    {
        const string trustedPath = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers";
        const string trustedStatusPath =
            "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-with-status";

        using var oldIssuer = NewKey();
        using var newIssuer = NewKey();
        using var holder = NewKey();
        string oldDid = Did(oldIssuer);
        string newDid = Did(newIssuer);
        string holderDid = Did(holder);
        string oldCredential = Issue(oldIssuer, oldDid, holderDid);
        string newCredential = Issue(newIssuer, newDid, holderDid);

        foreach (var (credential, expectedSigner) in new[]
        {
            (oldCredential, oldDid), (newCredential, newDid)
        })
        {
            using var accepted = await _client.AuthorizedPostAsJsonAsync(trustedPath, new
            {
                credential, trustedIssuerDids = new[] { oldDid, newDid },
                expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary.AbsoluteUri
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            var body = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
            Assert.Equal(expectedSigner, body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());
        }

        DateTimeOffset observed = TimeProvider.System.GetUtcNow();
        string cleanStatus = JwtVcJsonRevocationSnapshot.Create(newDid, [],
            Seed(newIssuer), observed, TimeProvider.System);
        string oldSignerStatus = JwtVcJsonRevocationSnapshot.Create(oldDid, [],
            Seed(oldIssuer), observed, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(newDid,
            [newCredential], Seed(newIssuer), observed, TimeProvider.System);

        foreach (var (snapshot, expected) in new[]
        {
            (cleanStatus, "SignedNotListed"), (oldSignerStatus, "Invalid"),
            (revoked, "Revoked")
        })
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(
                trustedStatusPath, new
                {
                    credential = newCredential, trustedIssuerDids = new[] { oldDid, newDid },
                    expectedHolderDid = holderDid,
                    expectedCredentialType = CredentialType,
                    subjectContextUri = Vocabulary.AbsoluteUri,
                    revocationSnapshot = snapshot
                }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal(expected, body.GetProperty("status").GetString());
            if (expected == "SignedNotListed")
            {
                Assert.Equal(newDid, body.GetProperty("verifiedIssuerDid").GetString());
                Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());
            }
            else
            {
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerDid").ValueKind);
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
            }
        }

        using var retired = await _client.AuthorizedPostAsJsonAsync(trustedPath, new
        {
            credential = oldCredential, trustedIssuerDids = new[] { newDid },
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary.AbsoluteUri
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, retired.StatusCode);
        var rejected = await retired.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedIssuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task HistoricalIssuerHttpRouteRequiresVerifierScopeAndRejectsAmbiguousPolicy()
    {
        const string route = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers";
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        var request = new
        {
            credential, trustedIssuerDids = new[] { issuerDid },
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary.AbsoluteUri
        };
        using var anonymous = await _client.PostAsJsonAsync(route, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        string issuanceOnly = await ScopeTokenAsync("credential:issue").ConfigureAwait(true);
        using var forbidden = await PostWithBearerAsync(route, request, issuanceOnly)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        using var ambiguous = await _client.AuthorizedPostAsJsonAsync(route, new
        {
            credential, trustedIssuerDids = new[] { issuerDid, issuerDid },
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary.AbsoluteUri
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, ambiguous.StatusCode);
    }

    [Fact]
    public async Task RetiredIssuerExactPinsAreEnforcedOverRealAuthenticatedHttp()
    {
        const string route = "/api/v1/credentials/jwt-vc-json/verify-active-and-retired";
        const string statusRoute =
            "/api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-status";

        using var retiredKey = NewKey();
        using var activeKey = NewKey();
        using var holderKey = NewKey();
        string retiredDid = Did(retiredKey);
        string activeDid = Did(activeKey);
        string holderDid = Did(holderKey);
        string oldJwt = Issue(retiredKey, retiredDid, holderDid);
        string activeJwt = Issue(activeKey, activeDid, holderDid);
        string pin = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(oldJwt)));
        var policy = new[]
        {
            new { issuerDid = retiredDid, credentialSha256 = pin }
        };

        foreach (var (credential, signer) in new[]
        {
            (oldJwt, retiredDid), (activeJwt, activeDid)
        })
        {
            using var accepted = await _client.AuthorizedPostAsJsonAsync(route, new
            {
                credential,
                activeIssuerDids = new[] { activeDid },
                retiredCredentialPins = policy,
                expectedHolderDid = holderDid,
                expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            var body = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
            Assert.Equal(signer, body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());
        }

        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string backdated = JwtVcJsonCredential.Create(retiredDid, holderDid,
            CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "administrator" }),
            Seed(retiredKey), now.AddMinutes(-1), now.AddMinutes(5));

        foreach (string unregistered in new[] { backdated, oldJwt })
        {
            using var rejected = await _client.AuthorizedPostAsJsonAsync(route, new
            {
                credential = unregistered,
                activeIssuerDids = new[] { activeDid },
                retiredCredentialPins = unregistered == oldJwt ? policy.Take(0).ToArray() : policy,
                expectedHolderDid = holderDid,
                expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
            var body = await rejected.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("Invalid", body.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerDid").ValueKind);
            Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
        }

        string fresh = JwtVcJsonRevocationSnapshot.Create(
            retiredDid, [], Seed(retiredKey), now, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            retiredDid, [oldJwt], Seed(retiredKey), now, TimeProvider.System);
        foreach (var (snapshot, expected) in new[]
        {
            (fresh, "SignedNotListed"), (revoked, "Revoked")
        })
        {
            using var status = await _client.AuthorizedPostAsJsonAsync(statusRoute, new
            {
                credential = oldJwt,
                activeIssuerDids = new[] { activeDid },
                retiredCredentialPins = policy,
                expectedHolderDid = holderDid,
                expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary,
                revocationSnapshot = snapshot
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, status.StatusCode);
            var body = await status.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal(expected, body.GetProperty("status").GetString());
            if (expected == "Revoked")
            {
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerDid").ValueKind);
            }
            else
            {
                Assert.Equal(retiredDid, body.GetProperty("verifiedIssuerDid").GetString());
                Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());
            }
        }

        var request = new
        {
            credential = oldJwt,
            activeIssuerDids = new[] { activeDid },
            retiredCredentialPins = policy,
            expectedHolderDid = holderDid,
            expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary
        };
        using var anonymous = await _client.PostAsJsonAsync(route, request).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        string issueOnly = await ScopeTokenAsync("credential:issue").ConfigureAwait(true);
        using var forbidden = await PostWithBearerAsync(route, request, issueOnly).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    private static object Request(string credential, string issuerDid, string holderDid,
        string type = CredentialType, Uri? context = null) => new
        {
            Credential = credential,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = type,
            SubjectContextUri = context ?? Vocabulary
        };

    private static object RequestWithStatus(string credential, string issuerDid,
        string holderDid, string snapshot) => new
        {
            Credential = credential,
            TrustedIssuerDid = issuerDid,
            ExpectedHolderDid = holderDid,
            ExpectedCredentialType = CredentialType,
            SubjectContextUri = Vocabulary,
            RevocationSnapshot = snapshot
        };

    private static string Issue(Key issuer, string issuerDid, string holderDid)
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        return JwtVcJsonCredential.Create(issuerDid, holderDid, CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
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
            "Obtain verifier token", "access_token").ConfigureAwait(true);
    }

    private async Task<HttpResponseMessage> PostWithBearerAsync(string path, object body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(request).ConfigureAwait(true);
    }

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static byte[] Seed(Key key) => key.Export(KeyBlobFormat.RawPrivateKey);

    private static string Did(Key key)
    {
        var encoded = new byte[34];
        encoded[0] = 0xed;
        encoded[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(encoded, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(encoded);
    }
}
