using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using NSec.Cryptography;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// Authenticated HTTP multi-issuer/recipient proof; not third-party wallet interoperability.
/// </summary>
public sealed class JwtVcJsonTrustedAudienceHttpTests(AspireWebApplicationFactory factory)
    : IClassFixture<AspireWebApplicationFactory>
{
    private const string VerifyPath = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-for-audience";
    private const string StatusPath = "/api/v1/credentials/jwt-vc-json/verify-trusted-issuers-for-audience-with-status";
    private const string CredentialType = "https://issuer.example/credentials#Membership";
    private static readonly Uri Context = new("https://issuer.example/contexts/member/v1");
    private static readonly Uri Recipient = new("https://verifier.example/credentials");
    private static readonly Uri OtherRecipient = new("https://other.example/credentials");
    private static readonly Uri Stranger = new("https://stranger.example/credentials");
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task CurrentAndHistoricalIssuersReleaseOnlyClaimsAddressedToThePinnedRecipient()
    {
        using var formerIssuer = NewKey();
        using var currentIssuer = NewKey();
        using var holder = NewKey();
        string formerDid = Did(formerIssuer);
        string currentDid = Did(currentIssuer);
        string holderDid = Did(holder);
        string[] pins = [formerDid, currentDid];
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (var (issuer, did) in new[] { (formerIssuer, formerDid), (currentIssuer, currentDid) })
        {
            string originalJwt = IssueForRecipients(issuer, did, holderDid, now);
            var request = new
            {
                credential = originalJwt, trustedIssuerDids = pins,
                expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
                subjectContextUri = Context, expectedAudience = Recipient
            };

            using var anonymous = await _client.PostAsJsonAsync(VerifyPath, request).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

            using var accepted = await _client.AuthorizedPostAsJsonAsync(VerifyPath, request)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            var body = await accepted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("SignedButStatusUnchecked", body.GetProperty("status").GetString());
            Assert.Equal(did, body.GetProperty("verifiedIssuerDid").GetString());
            Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());

            using var wrongRecipient = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
            {
                request.credential, request.trustedIssuerDids, request.expectedHolderDid,
                request.expectedCredentialType, request.subjectContextUri,
                expectedAudience = Stranger
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, wrongRecipient.StatusCode);
            var rejected = await wrongRecipient.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("Invalid", rejected.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, rejected.GetProperty("verifiedSubject").ValueKind);

            using var untrusted = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
            {
                request.credential, trustedIssuerDids = new[] { did == formerDid ? currentDid : formerDid },
                request.expectedHolderDid, request.expectedCredentialType,
                request.subjectContextUri, request.expectedAudience
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, untrusted.StatusCode);
            var untrustedBody = await untrusted.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal("Invalid", untrustedBody.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, untrustedBody.GetProperty("verifiedSubject").ValueKind);

            using var missingAudience = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
            {
                request.credential, request.trustedIssuerDids, request.expectedHolderDid,
                request.expectedCredentialType, request.subjectContextUri
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.BadRequest, missingAudience.StatusCode);
        }
    }

    [Fact]
    public async Task OnlyOriginalSignerStatusCanClearRecipientBoundCredential()
    {
        using var issuer = NewKey();
        using var otherIssuer = NewKey();
        using var holder = NewKey();
        string issuerDid = Did(issuer);
        string otherDid = Did(otherIssuer);
        string holderDid = Did(holder);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string original = IssueForRecipients(issuer, issuerDid, holderDid, now);
        string clean = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuer.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        string foreign = JwtVcJsonRevocationSnapshot.Create(otherDid, [],
            otherIssuer.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        string revoked = JwtVcJsonRevocationSnapshot.Create(issuerDid, [original],
            issuer.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        string[] pins = [issuerDid, otherDid];

        foreach (var (snapshot, expected) in new[]
        {
            (clean, "SignedNotListed"), (foreign, "Invalid"), (revoked, "Revoked")
        })
        {
            using var response = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
            {
                credential = original, trustedIssuerDids = pins,
                expectedHolderDid = holderDid, expectedCredentialType = CredentialType,
                subjectContextUri = Context, expectedAudience = Recipient,
                revocationSnapshot = snapshot
            }).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
            Assert.Equal(expected, body.GetProperty("status").GetString());
            if (expected == "SignedNotListed")
            {
                Assert.Equal(issuerDid, body.GetProperty("verifiedIssuerDid").GetString());
                Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());
            }
            else
            {
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedSubject").ValueKind);
                Assert.Equal(JsonValueKind.Null, body.GetProperty("verifiedIssuerDid").ValueKind);
            }
        }

        using var ignoredStatus = await _client.AuthorizedPostAsJsonAsync(VerifyPath, new
        {
            credential = original, trustedIssuerDids = pins, expectedHolderDid = holderDid,
            expectedCredentialType = CredentialType, subjectContextUri = Context,
            expectedAudience = Recipient, revocationSnapshot = clean
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, ignoredStatus.StatusCode);

        using var cutoff = await _client.AuthorizedPostAsJsonAsync(StatusPath, new
        {
            credential = original, trustedIssuerDids = pins, expectedHolderDid = holderDid,
            expectedCredentialType = CredentialType, subjectContextUri = Context,
            expectedAudience = Recipient, revocationSnapshot = clean,
            minimumStatusObservedAt = now.AddSeconds(5)
        }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, cutoff.StatusCode);
    }

    private static string IssueForRecipients(Key issuer, string issuerDid,
        string holderDid, DateTimeOffset now) =>
        JwtVcJsonCredential.CreateForAudiencesWithMetadata(issuerDid, holderDid,
            CredentialType, Context,
            JsonSerializer.SerializeToElement(new { id = holderDid, role = "member" }),
            issuer.Export(KeyBlobFormat.RawPrivateKey), now.AddMinutes(-1),
            now.AddMinutes(5), [Recipient, OtherRecipient], null, null, false);

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
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
