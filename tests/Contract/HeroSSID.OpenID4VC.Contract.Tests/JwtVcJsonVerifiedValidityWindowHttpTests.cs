using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Non-.NET verifier clients receive only authenticated, non-revoked JWT validity.</summary>
public sealed class JwtVcJsonVerifiedValidityWindowHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify";
    private const string StatusPath = "/api/v1/credentials/jwt-vc-json/verify-with-status";
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task VerifiedHttpTimeWindowIsExactAndWithheldOnInvalidOrRevokedCredential()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var otherIssuer = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        byte[] seed = issuer.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
                new { id = holderDid, membership = "active" }));
            DateTimeOffset now = TimeProvider.System.GetUtcNow();
            DateTimeOffset validFrom = now.AddMinutes(-1).AddTicks(1_234_567);
            DateTimeOffset validUntil = now.AddMinutes(4).AddTicks(7_654_321);
            string jwt = JwtVcJsonCredential.CreateWithExactValidity(
                issuerDid, holderDid, CredentialType, Vocabulary, subject.RootElement,
                seed, validFrom, validUntil);

            using var accepted = await _client.AuthorizedPostAsJsonAsync(
                VerifyPath, Request(jwt, issuerDid, holderDid)).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            JsonElement acceptedBody = await accepted.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked",
                acceptedBody.GetProperty("status").GetString());
            Assert.Equal(validFrom,
                acceptedBody.GetProperty("verifiedNotBefore").GetDateTimeOffset());
            Assert.Equal(validUntil,
                acceptedBody.GetProperty("verifiedExpiresAt").GetDateTimeOffset());

            string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
                seed, TimeProvider.System.GetUtcNow(), TimeProvider.System);
            using var cleanResponse = await _client.AuthorizedPostAsJsonAsync(
                StatusPath, RequestWithStatus(jwt, issuerDid, holderDid, clean))
                .ConfigureAwait(true);
            JsonElement cleanBody = await cleanResponse.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("SignedNotListed", cleanBody.GetProperty("status").GetString());
            Assert.Equal(validFrom, cleanBody.GetProperty("verifiedNotBefore").GetDateTimeOffset());
            Assert.Equal(validUntil, cleanBody.GetProperty("verifiedExpiresAt").GetDateTimeOffset());

            string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [jwt],
                seed, TimeProvider.System.GetUtcNow(), TimeProvider.System);
            using var denied = await _client.AuthorizedPostAsJsonAsync(
                StatusPath, RequestWithStatus(jwt, issuerDid, holderDid, revoked))
                .ConfigureAwait(true);
            JsonElement revokedBody = await denied.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("Revoked", revokedBody.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedNotBefore").ValueKind);
            Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedExpiresAt").ValueKind);

            using var invalid = await _client.AuthorizedPostAsJsonAsync(
                VerifyPath, Request(jwt, Did(otherIssuer), holderDid)).ConfigureAwait(true);
            JsonElement invalidBody = await invalid.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("Invalid", invalidBody.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, invalidBody.GetProperty("verifiedNotBefore").ValueKind);
            Assert.Equal(JsonValueKind.Null, invalidBody.GetProperty("verifiedExpiresAt").ValueKind);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static object Request(string jwt, string issuer, string holder) => new
    {
        credential = jwt, trustedIssuerDid = issuer,
        expectedHolderDid = holder, expectedCredentialType = CredentialType,
        subjectContextUri = Vocabulary
    };

    private static object RequestWithStatus(string jwt, string issuer, string holder,
        string snapshot) => new
    {
        credential = jwt, trustedIssuerDid = issuer,
        expectedHolderDid = holder, expectedCredentialType = CredentialType,
        subjectContextUri = Vocabulary, revocationSnapshot = snapshot
    };

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string Did(Key key)
    {
        var multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(multicodec, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec);
    }
}
