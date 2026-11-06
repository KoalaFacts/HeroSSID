using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Real authenticated HTTP contract: the consumer, not a JWT, pins the issuer
/// description and exact credential ID before it receives signed claims.
/// Not proof of legal identity, holder possession or external Wallet interop.
/// </summary>
public sealed class JwtVcJsonPinnedIssuerNameIdHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify-pinned-issuer-name-and-id";
    private const string StatusPath = "/api/v1/credentials/jwt-vc-json/verify-pinned-issuer-name-and-id-with-status";
    private const string LegacyPath = "/api/v1/credentials/jwt-vc-json/verify";
    private const string Type = "https://issuer.example/credentials#Membership";
    private const string Name = "Australasian Membership Registry";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member-041");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task OptInRouteReleasesRealSignedClaimsOnlyWhenEveryIndependentPinMatches()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);

        var goodPolicy = new
        {
            credential,
            trustedIssuerDid = issuerDid,
            expectedHolderDid = holderDid,
            expectedCredentialType = Type,
            subjectContextUri = Vocabulary,
            expectedIssuerName = Name,
            expectedCredentialId = CredentialId
        };

        using var anonymous = await _client.PostAsJsonAsync(VerifyPath, goodPolicy)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using var accepted = await _client.AuthorizedPostAsJsonAsync(VerifyPath, goodPolicy)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var ok = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", ok.GetProperty("status").GetString());
        Assert.Equal("member", ok.GetProperty("verifiedSubject").GetProperty("role").GetString());
        Assert.Equal(Name, ok.GetProperty("verifiedIssuerName").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, ok.GetProperty("verifiedCredentialId").GetString());
        Assert.Equal(JsonValueKind.String, ok.GetProperty("verifiedExpiresAt").ValueKind);

        // Signed statements remain authentic, yet must not escape wrong verifier policy.
        using var wrongName = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            goodPolicy.credential, goodPolicy.trustedIssuerDid, goodPolicy.expectedHolderDid,
            goodPolicy.expectedCredentialType, goodPolicy.subjectContextUri,
            expectedIssuerName = "Another Registry", goodPolicy.expectedCredentialId
        }).ConfigureAwait(true);
        await AssertRejectedAsync(wrongName, "Invalid").ConfigureAwait(true);

        using var wrongId = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            goodPolicy.credential, goodPolicy.trustedIssuerDid, goodPolicy.expectedHolderDid,
            goodPolicy.expectedCredentialType, goodPolicy.subjectContextUri,
            goodPolicy.expectedIssuerName,
            expectedCredentialId = new Uri("https://issuer.example/credentials/member-042")
        }).ConfigureAwait(true);
        await AssertRejectedAsync(wrongId, "Invalid").ConfigureAwait(true);

        using var foreignIssuer = NewKey();
        using var foreign = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential = Issue(foreignIssuer, Did(foreignIssuer), holderDid),
            goodPolicy.trustedIssuerDid, goodPolicy.expectedHolderDid,
            goodPolicy.expectedCredentialType, goodPolicy.subjectContextUri,
            goodPolicy.expectedIssuerName, goodPolicy.expectedCredentialId
        }).ConfigureAwait(true);
        await AssertRejectedAsync(foreign, "Invalid").ConfigureAwait(true);

        using var tampered = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential = credential + "x",
            goodPolicy.trustedIssuerDid, goodPolicy.expectedHolderDid,
            goodPolicy.expectedCredentialType, goodPolicy.subjectContextUri,
            goodPolicy.expectedIssuerName, goodPolicy.expectedCredentialId
        }).ConfigureAwait(true);
        await AssertRejectedAsync(tampered, "Invalid").ConfigureAwait(true);
    }

    [Fact]
    public async Task StatusRouteChecksSameOriginalIssuerAndNeverReleasesRevokedClaims()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var foreign = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        string clean = JwtVcJsonRevocationSnapshot.Create(
            issuerDid, [], Seed(issuer), now, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            issuerDid, [credential], Seed(issuer), now, TimeProvider.System);
        string foreignStatus = JwtVcJsonRevocationSnapshot.Create(
            Did(foreign), [], Seed(foreign), now, TimeProvider.System);

        foreach (var attempt in new[]
        {
            (Snapshot: clean, Expected: "SignedNotListed", HasClaims: true),
            (Snapshot: revoked, Expected: "Revoked", HasClaims: false),
            (Snapshot: foreignStatus, Expected: "Invalid", HasClaims: false)
        })
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
            {
                credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
                expectedCredentialType = Type, subjectContextUri = Vocabulary,
                expectedIssuerName = Name, expectedCredentialId = CredentialId,
                revocationSnapshot = attempt.Snapshot
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal(attempt.Expected, body.GetProperty("status").GetString());
            Assert.Equal(attempt.HasClaims ? JsonValueKind.Object : JsonValueKind.Null,
                body.GetProperty("verifiedSubject").ValueKind);
        }

        using var noStatus = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = Type, subjectContextUri = Vocabulary,
            expectedIssuerName = Name, expectedCredentialId = CredentialId
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, noStatus.StatusCode);
    }

    [Fact]
    public async Task MissingOrUnsafePinsAndLegacyRouteCannotSilentlyIgnoreRequestedPolicy()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        string credential = Issue(issuer, issuerDid, holderDid);

        using var missing = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = Type, subjectContextUri = Vocabulary,
            expectedCredentialId = CredentialId
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        using var unsafeId = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = Type, subjectContextUri = Vocabulary,
            expectedIssuerName = Name,
            expectedCredentialId = new Uri("http://issuer.example/credentials/member-041")
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, unsafeId.StatusCode);

        using var unexpectedStatus = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = Type, subjectContextUri = Vocabulary,
            expectedIssuerName = Name, expectedCredentialId = CredentialId,
            revocationSnapshot = "not-a-snapshot"
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, unexpectedStatus.StatusCode);

        // Before this feature, legacy HTTP verification would silently ignore
        // independent issuer-name and ID policy and return the signed subject.
        using var legacy = await _client.AuthorizedPostAsJsonAsync(LegacyPath, new
        {
            credential, trustedIssuerDid = issuerDid, expectedHolderDid = holderDid,
            expectedCredentialType = Type, subjectContextUri = Vocabulary,
            expectedIssuerName = "Wrong policy name",
            expectedCredentialId = CredentialId
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, legacy.StatusCode);
    }

    private static async Task AssertRejectedAsync(HttpResponseMessage response, string status)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        Assert.Equal(status, body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
        Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerName").ValueKind);
        Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedCredentialId").ValueKind);
    }

    private static string Issue(Key key, string issuerDid, string holderDid)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return JwtVcJsonCredential.CreateWithIssuerName(
            issuerDid, holderDid, Type, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            Seed(key), now.AddMinutes(-1), now.AddMinutes(4),
            Name, CredentialId, exactValidity: false);
    }

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static byte[] Seed(Key key) => key.Export(KeyBlobFormat.RawPrivateKey);

    private static string Did(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
