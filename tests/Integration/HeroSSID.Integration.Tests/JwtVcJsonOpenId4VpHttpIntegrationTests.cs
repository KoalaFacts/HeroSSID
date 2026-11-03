using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
using HeroSSID.Integration.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Integration.Tests;

/// <summary>
/// Authenticated OpenID4VP 1.0 jwt_vc_json direct_post HTTP adapter, tested with
/// three distinct real Ed25519 signers and disposable PostgreSQL challenges.
/// This is not an independent wallet interoperability or human consent test.
/// </summary>
public sealed class JwtVcJsonOpenId4VpHttpIntegrationTests(DatabaseFixture fixture)
    : IClassFixture<DatabaseFixture>
{
    private const string IssueRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/signed-request";
    private const string VerifyRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/verify-response";
    private const string HostedVerifyRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/verify-hosted-response";
    private const string CancelRoute = "/api/v1/credentials/jwt-vc-json/openid4vp/cancel-request";
    private const string ResponseUri = "https://verifier.example/direct-post";
    private const string TypeIri = "https://issuer.example/credentials#MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private readonly DatabaseFixture _fixture = fixture;

    [Fact]
    public async Task HostedStrictVerifierRequiresOriginalRequestBoundHolderProof()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120, publishRequestUri = true
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var payload = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = payload.GetProperty("signedRequestJwt").GetString()!;
        string nonce = payload.GetProperty("nonce").GetString()!;
        string launch = payload.GetProperty("referenceWalletInvocationUri").GetString()!;
        int index = launch.IndexOf("&request_uri=", StringComparison.Ordinal);
        Assert.True(index > 0);
        Uri published = new(Uri.UnescapeDataString(launch[(index + "&request_uri=".Length)..]));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "trusted-member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        byte[] holderSeed = holderKey.Export(KeyBlobFormat.RawPrivateKey);
        string unbound = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, credential,
            holderDid, holderSeed, TimeProvider.System);
        string bound = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, credential,
            holderDid, holderSeed, TimeProvider.System);

        // A published original request must not be bypassed via the legacy,
        // unbound verification route. A malicious caller with verification
        // scope must not receive claims or spend the live hosted challenge.
        using var legacyDowngrade = await PostAsync(client, VerifyRoute, new
        {
            verifierDid, nonce, form = unbound, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, legacyDowngrade.StatusCode);
        var legacyDowngradeBody = await legacyDowngrade.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", legacyDowngradeBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null,
            legacyDowngradeBody.GetProperty("verifiedSubject").ValueKind);

        using var rejected = await PostAsync(client, HostedVerifyRoute, new
        {
            verifierDid, nonce, form = unbound, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        var rejectedBody = await rejected.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", rejectedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, rejectedBody.GetProperty("verifiedSubject").ValueKind);

        // An invalid/unbound attempt must not spend the independently stored nonce.
        using var stillHosted = await client.GetAsync(published.PathAndQuery,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, stillHosted.StatusCode);

        using var substitutedPolicy = await PostAsync(client, HostedVerifyRoute, new
        {
            verifierDid, nonce, form = bound, revocationSnapshot = status,
            expectedCredentialType = "https://issuer.example/credentials#Wrong",
            subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        var substitutionBody = await substitutedPolicy.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", substitutionBody.GetProperty("status").GetString());

        var submitted = new
        {
            verifierDid, nonce, form = bound, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };
        using var accepted = await PostAsync(client, HostedVerifyRoute, submitted, token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var acceptedBody = await accepted.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", acceptedBody.GetProperty("status").GetString());
        Assert.Equal("trusted-member",
            acceptedBody.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await PostAsync(client, HostedVerifyRoute, submitted, token)
            .ConfigureAwait(true);
        var replayBody = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        using var retired = await client.GetAsync(published.PathAndQuery,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, retired.StatusCode);
    }

    [Fact]
    public async Task HostedStrictVerifierDoesNotDowngradeToUnpublishedByValueRequest()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120, publishRequestUri = false
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var details = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = details.GetProperty("signedRequestJwt").GetString()!;
        string nonce = details.GetProperty("nonce").GetString()!;
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string bound = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, credential,
            holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string legacyUnbound = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, credential,
            holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        var submitted = new
        {
            verifierDid, nonce, form = bound, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };

        using var denied = await PostAsync(client, HostedVerifyRoute, submitted, token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedBody = await denied.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", deniedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedBody.GetProperty("verifiedSubject").ValueKind);

        // Strict route denial must neither consume nor silently switch policy.
        using var legacy = await PostAsync(client, VerifyRoute, new
        {
            verifierDid, nonce, form = legacyUnbound, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        var legacyBody = await legacy.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", legacyBody.GetProperty("status").GetString());
    }

    [Fact]
    public async Task SignedVerifierRequestOffersUsableByValueWalletLaunchWithoutChangingSignedPolicy()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var body = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = body.GetProperty("signedRequestJwt").GetString()!;
        string launch = body.GetProperty("walletInvocationUri").GetString()!;

        const string prefix = "openid4vp://?client_id=";
        Assert.StartsWith(prefix, launch, StringComparison.Ordinal);
        string[] parameters = launch[prefix.Length..].Split("&request=", StringSplitOptions.None);
        Assert.Equal(2, parameters.Length);
        Assert.Equal(Uri.EscapeDataString("decentralized_identifier:" + verifierDid), parameters[0]);
        Assert.Equal(signed, Uri.UnescapeDataString(parameters[1]));
        Assert.True(OpenId4VpJwtVcJsonDirectPost.TryReadWalletInvocation(
            launch, verifierDid, new Uri(ResponseUri), TypeIri, Context,
            TimeProvider.System, out string recovered));
        Assert.Equal(signed, recovered);
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadWalletInvocation(
            launch + "&request=duplicate", verifierDid, new Uri(ResponseUri),
            TypeIri, Context, TimeProvider.System, out _));
        Assert.True(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, TimeProvider.System,
            out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(issuerDid, parsed.Challenge.TrustedIssuerDid);
    }

    [Fact]
    public async Task OptInPublicGetReturnsExactOriginalJwtAndStopsAfterCancellation()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120, publishRequestUri = true
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var body = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string jwt = body.GetProperty("signedRequestJwt").GetString()!;
        string nonce = body.GetProperty("nonce").GetString()!;
        string invocation = body.GetProperty("referenceWalletInvocationUri").GetString()!;
        Assert.StartsWith("openid4vp://?client_id=", invocation, StringComparison.Ordinal);
        Assert.DoesNotContain(jwt, invocation, StringComparison.Ordinal);
        int start = invocation.IndexOf("&request_uri=", StringComparison.Ordinal);
        Assert.True(start > 0);
        var publishedUri = new Uri(Uri.UnescapeDataString(
            invocation[(start + "&request_uri=".Length)..]));
        Assert.Equal("https", publishedUri.Scheme);
        Assert.StartsWith("/api/v1/credentials/jwt-vc-json/openid4vp/requests/",
            publishedUri.AbsolutePath, StringComparison.Ordinal);

        // The wallet's GET is anonymous, while publication required both scopes.
        using var fetched = await client.GetAsync(publishedUri.PathAndQuery,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, fetched.StatusCode);
        Assert.Equal("application/oauth-authz-req+jwt",
            fetched.Content.Headers.ContentType?.MediaType);
        Assert.Contains("no-store", fetched.Headers.CacheControl?.ToString(),
            StringComparison.Ordinal);
        Assert.Equal(jwt, await fetched.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true));

        using var cancelled = await PostAsync(client, CancelRoute,
            new { verifierDid, nonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var rejected = await client.GetAsync(publishedUri.PathAndQuery,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, rejected.StatusCode);
        using var unknown = await client.GetAsync(
            "/api/v1/credentials/jwt-vc-json/openid4vp/requests/" + new string('A', 43),
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task CancelledPublishedRequestImmediatelyReturnsItsBoundedHostCapacity()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);

        var requestObjects = host.Services
            .GetRequiredService<OpenId4VpJwtVcJsonRequestObjectStore>();
        // Reservations never issue a persistent challenge. Fill the remaining
        // 255 slots to expose stale published-entry capacity leaks, not PG quota.
        var reservations = Enumerable.Range(0, 255)
            .Select(_ => requestObjects.Reserve()).ToArray();
        try
        {
            var input = new
            {
                verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
                credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
                lifetimeSeconds = 120, publishRequestUri = true
            };
            using var issued = await PostAsync(client, IssueRoute, input, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
            var details = await issued.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
            string nonce = details.GetProperty("nonce").GetString()!;

            using var full = await PostAsync(client, IssueRoute, input, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.TooManyRequests, full.StatusCode);

            using var cancelled = await PostAsync(client, CancelRoute,
                new { verifierDid, nonce }, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);

            // A cancelled, no-longer-retrievable Request Object must not
            // occupy a volatile publication slot until its original expiry.
            using var replacement = await PostAsync(client, IssueRoute, input, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Created, replacement.StatusCode);
        }
        finally
        {
            foreach (string reference in reservations)
            {
                requestObjects.ReleaseReservation(reference);
            }
        }
    }

    [Fact]
    public async Task AcceptedPublishedHolderProofReclaimsTheHostSlotWithoutDroppingOtherReservations()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        var input = new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120, publishRequestUri = true
        };
        using var issued = await PostAsync(client, IssueRoute, input, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var issuedBody = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string jwt = issuedBody.GetProperty("signedRequestJwt").GetString()!;
        string nonce = issuedBody.GetProperty("nonce").GetString()!;
        string launch = issuedBody.GetProperty("referenceWalletInvocationUri").GetString()!;
        int offset = launch.IndexOf("&request_uri=", StringComparison.Ordinal);
        Assert.True(offset > 0);
        string url = Uri.UnescapeDataString(launch[(offset + "&request_uri=".Length)..]);
        var published = new Uri(url);

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            jwt, verifierDid, new Uri(ResponseUri), TypeIri, Context, credential, holderDid,
            holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);
        var requestObjects = host.Services
            .GetRequiredService<OpenId4VpJwtVcJsonRequestObjectStore>();
        string[] reservations = Enumerable.Range(0, 255)
            .Select(_ => requestObjects.Reserve()).ToArray();
        try
        {
            using var full = await PostAsync(client, IssueRoute, input, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.TooManyRequests, full.StatusCode);
            using var accepted = await PostAsync(client, HostedVerifyRoute, new
            {
                verifierDid, nonce, form, revocationSnapshot = status,
                expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
            }, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            var result = await accepted.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
            Assert.Equal("SignedNotListed", result.GetProperty("status").GetString());
            using var retired = await client.GetAsync(published.PathAndQuery,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.NotFound, retired.StatusCode);
            using var replacement = await PostAsync(client, IssueRoute, input, token)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Created, replacement.StatusCode);
        }
        finally
        {
            foreach (string reservation in reservations)
            {
                requestObjects.ReleaseReservation(reservation);
            }
        }
    }

    [Fact]
    public async Task SignedRequestAndIndependentHolderResponseVerifyOnceWithIssuerStatus()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var issuedBody = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string signed = issuedBody.GetProperty("signedRequestJwt").GetString()!;
        string nonce = issuedBody.GetProperty("nonce").GetString()!;
        Assert.Equal("decentralized_identifier:" + verifierDid,
            issuedBody.GetProperty("clientId").GetString());
        Assert.True(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, TimeProvider.System,
            out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(issuerDid, parsed.Challenge.TrustedIssuerDid);
        Assert.Equal(nonce, parsed.Challenge.Nonce);
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, holderDid, new Uri(ResponseUri), TypeIri, Context, TimeProvider.System, out _));
        Assert.False(OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
            signed, verifierDid, new Uri("https://other.example/callback"), TypeIri,
            Context, TimeProvider.System, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string original = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string holderForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signed, verifierDid, new Uri(ResponseUri), TypeIri, Context, original,
            holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System.GetUtcNow(),
            TimeProvider.System);
        var submitted = new
        {
            verifierDid, nonce, form = holderForm, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };
        using var verified = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var body = await verified.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", body.GetProperty("status").GetString());
        Assert.Equal("member", body.GetProperty("verifiedSubject").GetProperty("role").GetString());

        using var replay = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        var replayBody = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayBody.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task AuthenticRevokedIssuerCredentialNeverReleasesHolderClaims()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);
        using var issued = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var details = await issued.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string nonce = details.GetProperty("nonce").GetString()!;
        string signedRequest = details.GetProperty("signedRequestJwt").GetString()!;

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "revoked-member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string holderForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            signedRequest, verifierDid, new Uri(ResponseUri), TypeIri, Context,
            credential, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System);
        string revokedStatus = JwtVcJsonRevocationSnapshot.Create(issuerDid,
            [credential], issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System.GetUtcNow(), TimeProvider.System);

        var submitted = new
        {
            verifierDid, nonce, form = holderForm, revocationSnapshot = revokedStatus,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        };
        using var denied = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedJson = await denied.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Revoked", deniedJson.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedJson.GetProperty("verifiedSubject").ValueKind);

        using var replay = await PostAsync(client, VerifyRoute, submitted, token).ConfigureAwait(true);
        var replayJson = await replay.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", replayJson.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, replayJson.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task NoBearerNoDualScopeForeignVerifierAndNonHttpsCallbackCannotIssue()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        using var unrelated = NewKey();
        string foreignDid = DidFromKey(unrelated);
        var request = new
        {
            verifierDid = foreignDid, responseUri = ResponseUri, trustedIssuerDid = foreignDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        };
        using var anonymous = await client.PostAsJsonAsync(IssueRoute, request,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        foreach (string scope in new[] { "credential:verify", "did:manage" })
        {
            string token = await GetTokenAsync(client, scope).ConfigureAwait(true);
            using var forbidden = await PostAsync(client, IssueRoute, request, token).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        string fullToken = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        using var foreign = await PostAsync(client, IssueRoute, request, fullToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        string ownedDid = await CreateDidAsync(client, fullToken).ConfigureAwait(true);
        using var insecure = await PostAsync(client, IssueRoute, new
        {
            verifierDid = ownedDid, responseUri = "http://verifier.example/direct-post",
            trustedIssuerDid = foreignDid, credentialType = TypeIri,
            subjectContextUri = Context.AbsoluteUri, lifetimeSeconds = 120
        }, fullToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, insecure.StatusCode);

        using var untrustedVerify = await client.PostAsJsonAsync(VerifyRoute, new
        {
            verifierDid = ownedDid, nonce = new string('A', 43), form = "state=a&vp_token=b",
            revocationSnapshot = "not-a-signed-snapshot", expectedCredentialType = TypeIri,
            subjectContextUri = Context.AbsoluteUri
        }, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, untrustedVerify.StatusCode);
    }


    [Fact]
    public async Task CancellationRevokesAnOutstandingSignedRequestButNotAnotherVerifiersChallenge()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        string differentVerifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        using var issuerKey = NewKey();
        using var holderKey = NewKey();
        string issuerDid = DidFromKey(issuerKey);
        string holderDid = DidFromKey(holderKey);

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holderDid, role = "member" }));
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        string credential = JwtVcJsonCredential.Create(issuerDid, holderDid, TypeIri,
            Context, subject.RootElement, issuerKey.Export(KeyBlobFormat.RawPrivateKey),
            now.AddMinutes(-1), now.AddMinutes(10));
        string status = JwtVcJsonRevocationSnapshot.Create(issuerDid, [],
            issuerKey.Export(KeyBlobFormat.RawPrivateKey), now, TimeProvider.System);

        using var first = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var firstBody = await first.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string firstNonce = firstBody.GetProperty("nonce").GetString()!;
        string firstRequest = firstBody.GetProperty("signedRequestJwt").GetString()!;
        string firstForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            firstRequest, verifierDid, new Uri(ResponseUri), TypeIri, Context,
            credential, holderDid, holderKey.Export(KeyBlobFormat.RawPrivateKey),
            TimeProvider.System);

        using var wrongVerifierCancellation = await PostAsync(client, CancelRoute,
            new { verifierDid = differentVerifierDid, nonce = firstNonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, wrongVerifierCancellation.StatusCode);

        using var allowed = await PostAsync(client, VerifyRoute, new
        {
            verifierDid, nonce = firstNonce, form = firstForm, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var allowedBody = await allowed.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("SignedNotListed", allowedBody.GetProperty("status").GetString());

        using var second = await PostAsync(client, IssueRoute, new
        {
            verifierDid, responseUri = ResponseUri, trustedIssuerDid = issuerDid,
            credentialType = TypeIri, subjectContextUri = Context.AbsoluteUri,
            lifetimeSeconds = 120
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        var secondBody = await second.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        string secondNonce = secondBody.GetProperty("nonce").GetString()!;
        string secondForm = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            secondBody.GetProperty("signedRequestJwt").GetString()!, verifierDid,
            new Uri(ResponseUri), TypeIri, Context, credential, holderDid,
            holderKey.Export(KeyBlobFormat.RawPrivateKey), TimeProvider.System);

        using var cancelled = await PostAsync(client, CancelRoute,
            new { verifierDid, nonce = secondNonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var repeatedCancellation = await PostAsync(client, CancelRoute,
            new { verifierDid, nonce = secondNonce }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, repeatedCancellation.StatusCode);

        using var denied = await PostAsync(client, VerifyRoute, new
        {
            verifierDid, nonce = secondNonce, form = secondForm, revocationSnapshot = status,
            expectedCredentialType = TypeIri, subjectContextUri = Context.AbsoluteUri
        }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var deniedBody = await denied.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Invalid", deniedBody.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, deniedBody.GetProperty("verifiedSubject").ValueKind);
    }

    [Fact]
    public async Task CancelRequestRequiresCredentialVerifyAndValidVerifierBoundNonce()
    {
        await EnsureMigratedAsync().ConfigureAwait(true);
        await using var host = NewHost();
        using var client = host.CreateClient();
        string token = await GetTokenAsync(client, "credential:verify did:manage").ConfigureAwait(true);
        string verifierDid = await CreateDidAsync(client, token).ConfigureAwait(true);
        var cancellation = new { verifierDid, nonce = new string('A', 43) };

        using var anonymous = await client.PostAsJsonAsync(CancelRoute, cancellation,
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        foreach (string scope in new[] { "credential:verify", "did:manage" })
        {
            string wrongScope = await GetTokenAsync(client, scope).ConfigureAwait(true);
            using var forbidden = await PostAsync(client, CancelRoute, cancellation, wrongScope)
                .ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        using var malformed = await PostAsync(client, CancelRoute,
            new { verifierDid, nonce = "bad" }, token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);

        using var unknown = await PostAsync(client, CancelRoute, cancellation, token)
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NoContent, unknown.StatusCode);
    }

    private async Task EnsureMigratedAsync()
    {
        await using var db = _fixture.CreateDbContext<HeroDbContext>();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest> NewHost() =>
        new ConfiguredHost(_fixture.ConnectionString);

    private sealed class ConfiguredHost(string connectionString)
        : WebApplicationFactory<HeroSSID.Api.Features.Dids.CreateDidRequest>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:HeroDb"] = connectionString,
                    ["HEROSSID_DB_PASSWORD"] = "test_password",
                    ["Jwt:Secret"] = "isolated-openid4vp-http-adapter-test-secret-with-at-least-32-bytes",
                    ["OpenId4Vp:PublicRequestUriBase"] =
                        "https://verifier.example/api/v1/credentials/jwt-vc-json/openid4vp/requests/"
                }));
        }
    }

    private static async Task<string> CreateDidAsync(HttpClient client, string token)
    {
        using var response = await PostAsync(client, "/api/v1/dids",
            new { method = "did:key", keyType = "Ed25519" }, token).ConfigureAwait(true);
        return await ReadStringAsync(response, HttpStatusCode.Created, "did").ConfigureAwait(true);
    }

    private static async Task<string> GetTokenAsync(HttpClient client, string scope)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test_client",
            ["client_secret"] = "test_secret",
            ["scope"] = scope
        });
        using var response = await client.PostAsync("/oauth2/token", form).ConfigureAwait(true);
        return await ReadStringAsync(response, HttpStatusCode.OK, "access_token").ConfigureAwait(true);
    }

    private static async Task<string> ReadStringAsync(
        HttpResponseMessage response, HttpStatusCode expected, string name)
    {
        string content = await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(response.StatusCode == expected,
            $"Expected {expected} but received {response.StatusCode}: {content}");
        using var json = JsonDocument.Parse(content);
        return json.RootElement.GetProperty(name).GetString()!;
    }

    private static async Task<HttpResponseMessage> PostAsync<T>(
        HttpClient client, string route, T body, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(true);
    }

    private static Key NewKey() =>
        Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed);
    }
}
