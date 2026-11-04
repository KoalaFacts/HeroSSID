using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Signed descriptive names are disclosure, not a trust anchor.</summary>
public sealed class JwtVcJsonVerifiedIssuerNameHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify";
    private const string StatusPath = "/api/v1/credentials/jwt-vc-json/verify-with-status";
    private const string CredentialType = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task SignedIssuerNameRequiresGenuineIssuerAndStatusBeforeHttpDisclosure()
    {
        using var issuer = NewKey();
        using var holder = NewKey();
        using var outsider = NewKey();
        string issuerDid = Did(issuer);
        string holderDid = Did(holder);
        byte[] seed = issuer.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
                new { id = holderDid, role = "member" }));
            DateTimeOffset now = TimeProvider.System.GetUtcNow();
            string jwt = JwtVcJsonCredential.CreateWithIssuerName(
                issuerDid, holderDid, CredentialType, Vocabulary, subject.RootElement,
                seed, now.AddMinutes(-1), now.AddMinutes(5), "Membership Office");

            using var verified = await _client.AuthorizedPostAsJsonAsync(
                VerifyPath, Request(jwt, issuerDid, holderDid)).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
            JsonElement body = await verified.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
            Assert.Equal("member", body.GetProperty("verifiedSubject")
                .GetProperty("role").GetString());
            Assert.Equal("Membership Office", body.GetProperty("verifiedIssuerName").GetString());

            string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
                seed, TimeProvider.System.GetUtcNow(), TimeProvider.System);
            using var accepted = await _client.AuthorizedPostAsJsonAsync(
                StatusPath, RequestWithStatus(jwt, issuerDid, holderDid, clean))
                .ConfigureAwait(true);
            JsonElement cleanBody = await accepted.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("SignedNotListed", cleanBody.GetProperty("status").GetString());
            Assert.Equal("Membership Office", cleanBody.GetProperty("verifiedIssuerName").GetString());

            string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [jwt],
                seed, TimeProvider.System.GetUtcNow(), TimeProvider.System);
            using var denied = await _client.AuthorizedPostAsJsonAsync(
                StatusPath, RequestWithStatus(jwt, issuerDid, holderDid, revoked))
                .ConfigureAwait(true);
            JsonElement revokedBody = await denied.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("Revoked", revokedBody.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedSubject").ValueKind);
            Assert.Equal(JsonValueKind.Null, revokedBody.GetProperty("verifiedIssuerName").ValueKind);

            string[] segments = jwt.Split('.');
            segments[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(jwt)
                .Replace("Membership Office", "Fake Govt Agency", StringComparison.Ordinal));
            foreach (object attempt in new[]
            {
                Request(string.Join('.', segments), issuerDid, holderDid),
                Request(jwt, Did(outsider), holderDid),
                Request(jwt, issuerDid, Did(outsider))
            })
            {
                using var rejected = await _client.AuthorizedPostAsJsonAsync(VerifyPath, attempt)
                    .ConfigureAwait(true);
                JsonElement invalid = await rejected.Content.ReadFromJsonAsync<JsonElement>()
                    .ConfigureAwait(true);
                Assert.Equal("Invalid", invalid.GetProperty("status").GetString());
                Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedSubject").ValueKind);
                Assert.Equal(JsonValueKind.Null, invalid.GetProperty("verifiedIssuerName").ValueKind);
            }

            string unnamed = JwtVcJsonCredential.Create(issuerDid, holderDid,
                CredentialType, Vocabulary, subject.RootElement, seed,
                now.AddMinutes(-1), now.AddMinutes(5));
            using var old = await _client.AuthorizedPostAsJsonAsync(
                VerifyPath, Request(unnamed, issuerDid, holderDid)).ConfigureAwait(true);
            JsonElement oldBody = await old.Content.ReadFromJsonAsync<JsonElement>()
                .ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked", oldBody.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, oldBody.GetProperty("verifiedIssuerName").ValueKind);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static object Request(string jwt, string issuerDid, string holderDid) => new
    {
        credential = jwt,
        trustedIssuerDid = issuerDid,
        expectedHolderDid = holderDid,
        expectedCredentialType = CredentialType,
        subjectContextUri = Vocabulary
    };

    private static object RequestWithStatus(string jwt, string issuerDid, string holderDid,
        string status) => new
    {
        credential = jwt,
        trustedIssuerDid = issuerDid,
        expectedHolderDid = holderDid,
        expectedCredentialType = CredentialType,
        subjectContextUri = Vocabulary,
        revocationSnapshot = status
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
