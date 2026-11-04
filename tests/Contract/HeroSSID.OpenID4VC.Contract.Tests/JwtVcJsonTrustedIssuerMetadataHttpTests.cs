using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Verified multi-issuer metadata is original signer evidence, not holder proof or business authority.</summary>
public sealed class JwtVcJsonTrustedIssuerMetadataHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string TrustedRoute = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers";
    private const string AudienceRoute = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-for-audience";
    private const string AudienceStatusRoute = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-for-audience-with-status";
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Recipient = new("https://verifier.example/membership");
    private static readonly Uri SecondRecipient = new("https://other.example/membership");
    private static readonly Uri WrongRecipient = new("https://stranger.example/membership");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/member-123");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task AudienceAndStatusReleaseExactSignedMetadataOnlyToRecipientAndPinnedSigner()
    {
        using var issuer = NewKey();
        using var other = NewKey();
        using var holder = NewKey();
        string did = Did(issuer);
        string holderDid = Did(holder);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        DateTimeOffset from = now.AddSeconds(-20).AddTicks(3);
        DateTimeOffset until = now.AddMinutes(5).AddTicks(7);
        string jwt = JwtVcJsonCredential.CreateForAudiencesWithMetadata(
            did, holderDid, CredentialType, Vocabulary,
            JsonSerializer.SerializeToElement(new { id = holderDid, membership = "active" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), from, until,
            [Recipient, SecondRecipient], CredentialId, "Membership Office", true);
        string clean = JwtVcJsonRevocationSnapshot.Create(did, [],
            issuer.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(did, [jwt],
            issuer.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);

        object request = new
        {
            credential = jwt, trustedIssuerDids = new[] { Did(other), did },
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary, expectedAudience = Recipient
        };
        using var accepted = await _client.AuthorizedPostAsJsonAsync(AudienceRoute, request)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement body = await accepted.Content.ReadFromJsonAsync<JsonElement>()
            .ConfigureAwait(true);
        AssertVerifiedMetadata(body, "SignedButStatusUnchecked", did, from, until);

        using var acceptedWithStatus = await _client.AuthorizedPostAsJsonAsync(
            AudienceStatusRoute, new
            {
                credential = jwt, trustedIssuerDids = new[] { Did(other), did },
                expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary, expectedAudience = Recipient,
                revocationSnapshot = clean
            }).ConfigureAwait(true);
        JsonElement statusBody = await acceptedWithStatus.Content.ReadFromJsonAsync<JsonElement>()
            .ConfigureAwait(true);
        AssertVerifiedMetadata(statusBody, "SignedNotListed", did, from, until);

        foreach (var (jwtAttempt, recipient, pins, status, route) in new[]
        {
            (jwt, WrongRecipient, new[] { did }, (string?)null, AudienceRoute),
            (jwt, Recipient, new[] { Did(other) }, (string?)null, AudienceRoute),
            (jwt[..^1] + (jwt[^1] == 'a' ? "b" : "a"), Recipient, new[] { did },
                (string?)null, AudienceRoute),
            (jwt, Recipient, new[] { did }, revoked, AudienceStatusRoute)
        })
        {
            using var rejected = await _client.AuthorizedPostAsJsonAsync(route, new
            {
                credential = jwtAttempt, trustedIssuerDids = pins,
                expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
                subjectContextUri = Vocabulary, expectedAudience = recipient,
                revocationSnapshot = status
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
            JsonElement invalid = await rejected.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal(status is null ? "Invalid" : "Revoked",
                invalid.GetProperty("status").GetString());
            Assert.Null(invalid.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedSubject").ValueKind);
            Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedCredentialId").ValueKind);
            Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedIssuerName").ValueKind);
            Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedNotBefore").ValueKind);
            Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedExpiresAt").ValueKind);
        }
    }

    [Fact]
    public async Task AudienceFreeTrustedIssuerVerificationReturnsExactSignedIdentifierAndValidity()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        string did = Did(issuer);
        string holderDid = Did(holder);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        DateTimeOffset from = now.AddSeconds(-20).AddTicks(1);
        DateTimeOffset until = now.AddMinutes(5).AddTicks(3);
        string jwt = JwtVcJsonCredential.CreateWithExactValidity(did, holderDid,
            CredentialType, Vocabulary, JsonSerializer.SerializeToElement(
                new { id = holderDid, membership = "active" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), from, until, CredentialId);

        using var accepted = await _client.AuthorizedPostAsJsonAsync(TrustedRoute, new
        {
            credential = jwt, trustedIssuerDids = new[] { did },
            expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
            subjectContextUri = Vocabulary
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        JsonElement body = await accepted.Content.ReadFromJsonAsync<JsonElement>()
            .ConfigureAwait(true);
        Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
        Assert.Equal(did, body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, body.GetProperty("verifiedCredentialId").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerName").ValueKind);
        Assert.Equal(from, body.GetProperty("verifiedNotBefore").GetDateTimeOffset());
        Assert.Equal(until, body.GetProperty("verifiedExpiresAt").GetDateTimeOffset());
    }

    private static void AssertVerifiedMetadata(JsonElement body, string status,
        string did, DateTimeOffset from, DateTimeOffset until)
    {
        Assert.Equal(status, body.GetProperty("status").GetString());
        Assert.Equal(did, body.GetProperty("verifiedIssuerDid").GetString());
        Assert.Equal("active", body.GetProperty("verifiedSubject")
            .GetProperty("membership").GetString());
        Assert.Equal(CredentialId.AbsoluteUri, body.GetProperty("verifiedCredentialId").GetString());
        Assert.Equal("Membership Office", body.GetProperty("verifiedIssuerName").GetString());
        Assert.Equal(from, body.GetProperty("verifiedNotBefore").GetDateTimeOffset());
        Assert.Equal(until, body.GetProperty("verifiedExpiresAt").GetDateTimeOffset());
    }

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string Did(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
