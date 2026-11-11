using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpJwtVcJsonRequestUriTests
{
    private const string Type = "https://issuer.example/credentials#Membership";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Callback = new("https://verifier.example/receive");
    private static readonly Uri RequestUri = new("https://verifier.example/oid4vp/requests/opaque");
    private readonly Clock _clock = new(new DateTimeOffset(2026, 11, 3, 4, 0, 0, TimeSpan.Zero));
    private readonly (byte[] Seed, string Did) _issuer = Identity();
    private readonly (byte[] Seed, string Did) _holder = Identity();
    private readonly (byte[] Seed, string Did) _verifier = Identity();
    private readonly (byte[] Seed, string Did) _attacker = Identity();

    [Fact]
    public async Task ByReferenceGetVerifiesRequestAndCompletesHolderBoundPresentation()
    {
        var tenant = Guid.NewGuid();
        string audience = "decentralized_identifier:" + _verifier.Did;
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.IssueHosted(tenant, audience, _issuer.Did);
        string signedRequest = SignedRequest(challenge);
        string invocation = ByReferenceLaunch(signedRequest);
        Assert.DoesNotContain(signedRequest, invocation, StringComparison.Ordinal);
        Assert.Contains("request_uri=", invocation, StringComparison.Ordinal);

        using var handler = new ProbeHandler(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(RequestUri, request.RequestUri);
            Assert.Contains(request.Headers.Accept, x =>
                x.MediaType == "application/oauth-authz-req+jwt");
            return JwtResponse(signedRequest);
        });
        using var http = new HttpClient(handler);
        string? fetched = await Resolve(invocation, RequestUri, http);
        Assert.Equal(signedRequest, fetched);
        Assert.Equal(1, handler.Calls);

        using var subject = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(new { id = _holder.Did, membership = "active" }));
        string credential = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, Type,
            Context, subject.RootElement, _issuer.Seed, _clock.GetUtcNow().AddSeconds(-5),
            _clock.GetUtcNow().AddMinutes(5));
        string form = OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            fetched!, _verifier.Did, Callback, Type, Context, credential,
            _holder.Did, _holder.Seed, _clock);
        string pin = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(signedRequest)));
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                form, fetched!, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                form, fetched!, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out _));
    }

    [Fact]
    public async Task NoFetchFromUntrustedOrAlteredLaunchAndForgedPayloadNeverPasses()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using var handler = new ProbeHandler(_ => JwtResponse(signed));
        using var http = new HttpClient(handler);

        Assert.Null(await Resolve(launch, new Uri("https://evil.example/oid4vp/requests/opaque"), http));
        Assert.Null(await Resolve(launch + "&request_uri=duplicate", RequestUri, http));
        Assert.Null(await Resolve(launch.Replace("https", "http", StringComparison.Ordinal),
            RequestUri, http));
        Assert.Null(await Resolve(launch.Replace("request_uri=", "request=", StringComparison.Ordinal),
            RequestUri, http));
        Assert.Equal(0, handler.Calls);

        string forged = HeroSSID.Credentials.Utilities.Ed25519JwtSigner.CreateSignedJwt(
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractHeader(signed),
            HeroSSID.Credentials.Utilities.Ed25519JwtSigner.ExtractPayload(signed),
            _attacker.Seed);
        using var forgeryHandler = new ProbeHandler(_ => JwtResponse(forged));
        using var forgeryHttp = new HttpClient(forgeryHandler);
        Assert.Null(await Resolve(launch, RequestUri, forgeryHttp));
        Assert.Equal(1, forgeryHandler.Calls);
    }

    [Fact]
    public async Task RejectsWrongContentTypeRedirectOversizedBodyAndExpiredRequest()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(signed, Encoding.UTF8, "text/html") }))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Redirect)
            { Headers = { Location = new Uri("https://evil.example/request") } }))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        using (var handler = new ProbeHandler(_ => JwtResponse(new string('x', 20_000))))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }

        _clock.Advance(TimeSpan.FromMinutes(6));
        using (var handler = new ProbeHandler(_ => JwtResponse(signed)))
        using (var http = new HttpClient(handler))
        {
            Assert.Null(await Resolve(launch, RequestUri, http));
        }
    }

    [Theory]
    [InlineData("Application/OAUTH-Authz-Req+JWT")]
    [InlineData("application/oauth-authz-req+jwt; charset=\"UTF-8\"")]
    [InlineData("APPLICATION/OAUTH-AUTHZ-REQ+JWT; CHARSET=utf-8")]
    public async Task FetchAcceptsEquivalentHttpRequestObjectMediaTypes(string mediaType)
    {
        // RFC 9110 permits case-insensitive type/subtype and charset names
        // as well as a quoted charset value. A genuine verifier must work
        // with independent, standards-conforming HTTP servers.
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using var handler = new ProbeHandler(_ =>
        {
            var response = JwtResponse(signed);
            response.Content.Headers.ContentType =
                System.Net.Http.Headers.MediaTypeHeaderValue.Parse(mediaType);
            return response;
        });
        using var http = new HttpClient(handler);

        Assert.Equal(signed, await Resolve(launch, RequestUri, http));
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData("application/oauth-authz-req+jwt; charset=utf-16")]
    [InlineData("application/oauth-authz-req+jwt; profile=untrusted")]
    [InlineData("application/json")]
    public async Task FetchRejectsNonEquivalentHttpRequestObjectMediaTypes(string mediaType)
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using var handler = new ProbeHandler(_ =>
        {
            var response = JwtResponse(signed);
            response.Content.Headers.ContentType =
                System.Net.Http.Headers.MediaTypeHeaderValue.Parse(mediaType);
            return response;
        });
        using var http = new HttpClient(handler);

        Assert.Null(await Resolve(launch, RequestUri, http));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task WalletDoesNotSendAmbientCredentialsToPublicRequestUri()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);

        // A shared application HttpClient may carry a bearer token or even
        // proprietary session headers. Never forward these to a public Request Object GET.
        using (var handler = new ProbeHandler(_ => JwtResponse(signed)))
        using (var http = new HttpClient(handler))
        {
            http.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "wallet-secret");
            Assert.Null(await Resolve(launch, RequestUri, http));
            Assert.Equal(0, handler.Calls);
        }

        using (var handler = new ProbeHandler(_ => JwtResponse(signed)))
        using (var http = new HttpClient(handler))
        {
            http.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", "secret");
            Assert.Null(await Resolve(launch, RequestUri, http));
            Assert.Equal(0, handler.Calls);
        }
    }

    [Fact]
    public void IsolatedRequestObjectHandlerCannotForwardCookiesAmbientCredentialsOrRedirects()
    {
        using var handler = OpenId4VpJwtVcJsonRequestUri.CreateIsolatedTransportHandler();
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.False(handler.PreAuthenticate);
        Assert.Null(handler.Credentials);
        Assert.False(handler.UseProxy);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.Null(handler.ActivityHeadersPropagator);
        Assert.Equal(System.Security.Cryptography.X509Certificates.X509RevocationMode.Online,
            handler.SslOptions.CertificateRevocationCheckMode);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.SslOptions.ClientCertificates);
        Assert.Null(handler.SslOptions.LocalCertificateSelectionCallback);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);

        using var http = new HttpClient(handler);
        Assert.Empty(http.DefaultRequestHeaders);
    }

    [Fact]
    public async Task IsolatedRequestObjectFetchStillRequiresExactTrustedSignedLaunch()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        // URI mismatch must fail before opening any network connection, even
        // when using the new self-managed credential-free transport.
        Assert.Null(await OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestWithIsolatedTransportAsync(
            launch, new Uri("https://evil.example/oid4vp/requests/opaque"),
            _verifier.Did, Callback, Type, Context, _clock));
    }

    [Fact]
    public async Task BoundedDeadlineStopsAStalledBodyWithNoCallerCancellation()
    {
        string signed = SignedRequest(new InMemoryPresentationChallengeStore(_clock)
            .IssueHosted(Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did));
        string launch = ByReferenceLaunch(signed);
        using var handler = new ProbeHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new NeverEndingStream())
            };
            response.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue(
                    "application/oauth-authz-req+jwt");
            return response;
        });
        using var http = new HttpClient(handler);
        Assert.Null(await OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestAsync(
            launch, RequestUri, http, _verifier.Did, Callback, Type, Context,
            _clock, maximumDuration: TimeSpan.FromMilliseconds(75)));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task OrdinaryByValueNonceCannotBeLaunchedOrFetchedAsHostedRequest()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var ordinary = store.Issue(Guid.NewGuid(),
            "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string signed = SignedRequest(ordinary);
        Assert.False(HostedPresentationChallengeNonce.IsHosted(ordinary.Nonce));
        Assert.Throws<ArgumentException>(() => ByReferenceLaunch(signed));

        string forgedLaunch = "openid4vp://?client_id=" +
            Uri.EscapeDataString("decentralized_identifier:" + _verifier.Did) +
            "&request_uri=" + Uri.EscapeDataString(RequestUri.OriginalString);
        using var handler = new ProbeHandler(_ => JwtResponse(signed));
        using var http = new HttpClient(handler);
        Assert.Null(await Resolve(forgedLaunch, RequestUri, http));
    }


    [Fact]
    public async Task WalletMustNotPostUnboundOrTamperedProofEvenWhenStateMatches()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        using var subject = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(new { id = _holder.Did, membership = "active" }));
        string credential = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
            Type, Context, subject.RootElement, _issuer.Seed,
            _clock.GetUtcNow().AddSeconds(-5), _clock.GetUtcNow().AddMinutes(5));
        string unbound = OpenId4VpJwtVcJsonDirectPost.CreateHolderResponseForm(
            requestJwt, _verifier.Did, Callback, Type, Context,
            credential, _holder.Did, _holder.Seed, _clock);
        string bound = HolderBoundForm(requestJwt);
        string malformed = "vp_token=x" + bound["vp_token=".Length..];

        using var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        foreach (string form in new[] { unbound, malformed })
        {
            Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
                requestJwt, form, Callback, http, _verifier.Did, Type, Context, _clock));
        }

        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task WalletRefusesCryptographicallyTamperedHolderJwtBeforeHttp()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        string originalForm = HolderBoundForm(requestJwt);
        int separator = originalForm.IndexOf('&', StringComparison.Ordinal);
        string json = WebUtility.UrlDecode(originalForm["vp_token=".Length..separator]);
        using var parsed = System.Text.Json.JsonDocument.Parse(json);
        string jwt = parsed.RootElement.GetProperty("jwt_vc_json_credential")[0].GetString()!;
        int signatureStart = jwt.AsSpan().LastIndexOf('.') + 1;
        char substitute = jwt[signatureStart] == 'A' ? 'B' : 'A';
        string tampered = jwt[..signatureStart] + substitute + jwt[(signatureStart + 1)..];
        string tokenJson = System.Text.Json.JsonSerializer.Serialize(
            new Dictionary<string, string[]> { ["jwt_vc_json_credential"] = [tampered] });
        string form = "vp_token=" + Uri.EscapeDataString(tokenJson) +
            "&state=" + Uri.EscapeDataString(challenge.Nonce);

        using var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            requestJwt, form, Callback, http, _verifier.Did, Type, Context, _clock));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task WalletRejectsDifferentGenuinelySignedRequestForSameNonceBeforeDisclosure()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string originalRequest = SignedRequest(challenge);
        _clock.Advance(TimeSpan.FromSeconds(1));
        string replacementRequest = SignedRequest(challenge);
        Assert.NotEqual(originalRequest, replacementRequest);
        string form = HolderBoundForm(replacementRequest);

        using var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            originalRequest, form, Callback, http, _verifier.Did, Type, Context, _clock));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task WalletPostsExactHolderSignedBodyOnlyToPinnedVerifierCallback()
    {
        Guid tenant = Guid.NewGuid();
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.IssueHosted(
            tenant, "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        string body = HolderBoundForm(requestJwt);
        using var handler = new ProbeHandler(request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(Callback, request.RequestUri);
            Assert.Null(request.Headers.Authorization);
            Assert.Equal("application/x-www-form-urlencoded",
                request.Content?.Headers.ContentType?.MediaType);
            Assert.Equal(body, request.Content!.ReadAsStringAsync().GetAwaiter().GetResult());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
        });
        using var http = new HttpClient(handler);
        Assert.True(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
        Assert.Equal(1, handler.Calls);

        // Wallet-side signature checks must not consume the verifier's challenge.
        string audience = "decentralized_identifier:" + _verifier.Did;
        string pin = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(requestJwt)));
        Assert.Equal(JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                body, requestJwt, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out _));
        Assert.Equal(JwtVcJsonPresentationCheckResult.Invalid,
            OpenId4VpJwtVcJsonDirectPost.CheckHolderBoundResponseForm(
                body, requestJwt, pin, _verifier.Did, Callback, tenant,
                audience, challenge.Nonce, Type, Context, store, _clock, out _));
    }

    [Fact]
    public async Task WalletDoesNotPostToUntrustedCallbackOrForwardAmbientCredentials()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        string body = HolderBoundForm(requestJwt);
        using var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var http = new HttpClient(handler);

        Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            requestJwt, body, new Uri("https://evil.example/collect"), http,
            _verifier.Did, Type, Context, _clock));
        Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            requestJwt, body.Replace("&state=", "&state=wrong-", StringComparison.Ordinal),
            Callback, http, _verifier.Did, Type, Context, _clock));

        http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "wallet-secret");
        Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task WalletRejectsRedirectAndFailedDirectPostDelivery()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        string body = HolderBoundForm(requestJwt);
        using (var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect)
            { Headers = { Location = new Uri("https://evil.example/collect") } }))
        using (var http = new HttpClient(handler))
        {
            Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
                requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
            Assert.Equal(1, handler.Calls);
        }

        using (var handler = new ProbeHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)))
        using (var http = new HttpClient(handler))
        {
            Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
                requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
        }
    }


    [Fact]
    public async Task WalletRejectsHtmlOrMalformedJsonReceiptAfterPosting()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string requestJwt = SignedRequest(challenge);
        string body = HolderBoundForm(requestJwt);
        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("<html>ok</html>", Encoding.UTF8, "text/html")
            }))
        using (var http = new HttpClient(handler))
        {
            Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
                requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
        }

        using (var handler = new ProbeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{", Encoding.UTF8, "application/json")
            }))
        using (var http = new HttpClient(handler))
        {
            Assert.False(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
                requestJwt, body, Callback, http, _verifier.Did, Type, Context, _clock));
        }
    }


    [Fact]
    public async Task WalletAcceptsSuccessfulReceiptWithQuotedUtf8Charset()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string signed = SignedRequest(challenge);
        string body = HolderBoundForm(signed);
        using var handler = new ProbeHandler(_ =>
        {
            var receipt = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            receipt.Content.Headers.ContentType =
                System.Net.Http.Headers.MediaTypeHeaderValue.Parse(
                    "application/json; charset=\"utf-8\"");
            return receipt;
        });
        using var http = new HttpClient(handler);
        Assert.True(await OpenId4VpJwtVcJsonWalletResponseTransport.PostResponseFormAsync(
            signed, body, Callback, http, _verifier.Did, Type, Context, _clock));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public void IsolatedDirectPostHandlerRejectsAmbientCredentialsAndTracePropagation()
    {
        using var activity = new System.Diagnostics.Activity("secret-wallet-tenant");
        activity.SetIdFormat(System.Diagnostics.ActivityIdFormat.W3C);
        activity.AddBaggage("private-tenant", "internal-account-name");
        activity.Start();
        using var handler =
            OpenId4VpJwtVcJsonWalletResponseTransport.CreateIsolatedDirectPostHandler();
        Assert.Null(handler.ActivityHeadersPropagator);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.False(handler.UseProxy);
        Assert.Null(handler.Credentials);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.False(handler.PreAuthenticate);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(System.Security.Cryptography.X509Certificates.X509RevocationMode.Online,
            handler.SslOptions.CertificateRevocationCheckMode);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.SslOptions.ClientCertificates);
        Assert.Null(handler.SslOptions.LocalCertificateSelectionCallback);
    }

    [Fact]
    public async Task IsolatedDirectPostHandlerDoesNotLeakActivityHeadersToRealLoopbackHttp()
    {
        // Exercise .NET's actual SocketsHttpHandler diagnostics pipeline, not a
        // fake HttpMessageHandler that would miss injected trace/baggage headers.
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var activity = new System.Diagnostics.Activity("wallet-sensitive-flow");
        activity.SetIdFormat(System.Diagnostics.ActivityIdFormat.W3C);
        activity.AddBaggage("tenant", "private-account-identifier");
        activity.Start();
        using var handler =
            OpenId4VpJwtVcJsonWalletResponseTransport.CreateIsolatedDirectPostHandler();
        // Test-only loopback connector: exercise real HTTP Activity diagnostics
        // without weakening the production public-only destination policy.
        handler.ConnectCallback = ConnectTestOnlyLoopbackAsync;
        using var http = new HttpClient(handler);
        // Start request before accepting the TCP connection. Await both the
        // real HTTP call and the server before leaving the using scopes.
        Task<HttpResponseMessage> requestTask = http.GetAsync(
            new Uri($"http://127.0.0.1:{port}/probe"), cancellation.Token);
        string received = await ReadHeadersAndReplyAsync(
            listener, cancellation.Token).ConfigureAwait(true);
        using var response = await requestTask.ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("traceparent:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tracestate:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("baggage:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private-account-identifier", received, StringComparison.Ordinal);
        listener.Stop();
    }

    [Fact]
    public async Task IsolatedRequestObjectGetNeverLeaksWalletActivityHeaders()
    {
        // Exercise the actual .NET HTTP pipeline over loopback. A fake
        // HttpMessageHandler cannot observe automatic trace/baggage propagation.
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var activity = new System.Diagnostics.Activity("wallet-request-uri");
        activity.SetIdFormat(System.Diagnostics.ActivityIdFormat.W3C);
        activity.AddBaggage("wallet-account", "private-wallet-tenant");
        activity.Start();

        using var handler = OpenId4VpJwtVcJsonRequestUri.CreateIsolatedTransportHandler();
        // Explicitly bypass the production egress policy only inside this
        // isolated trace-header test against a private local TCP listener.
        handler.ConnectCallback = ConnectTestOnlyLoopbackAsync;
        using var http = new HttpClient(handler);
        Task<HttpResponseMessage> requestTask = http.GetAsync(
            new Uri($"http://127.0.0.1:{port}/request-object"), cancellation.Token);
        string received = await ReadHeadersAndReplyAsync(listener, cancellation.Token)
            .ConfigureAwait(true);
        using var response = await requestTask.ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("traceparent:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tracestate:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("baggage:", received, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private-wallet-tenant", received, StringComparison.Ordinal);
        listener.Stop();
    }

    private static async ValueTask<Stream> ConnectTestOnlyLoopbackAsync(
        System.Net.Http.SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        // Only these two header-propagation tests override a production
        // handler. Do not use this connector in Wallet application code.
        System.Net.Sockets.Socket? socket = new(
            AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(
                IPAddress.Loopback, context.DnsEndPoint.Port, cancellationToken)
                .ConfigureAwait(false);
            var stream = new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
            socket = null;
            return stream;
        }
        finally
        {
            socket?.Dispose();
        }
    }

    private static async Task<string> ReadHeadersAndReplyAsync(
        System.Net.Sockets.TcpListener listener, CancellationToken cancellationToken)
    {
        using var connection = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
        using var stream = connection.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        var headers = new List<string>();
        while (true)
        {
            string? line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null || line.Length == 0)
            {
                break;
            }

            headers.Add(line);
        }

        byte[] response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return string.Join("\n", headers);
    }

    [Fact]
    public async Task PinnedBaseResolvesOpaqueRequestAndAuthenticatesSignedVerifier()
    {
        var store = new InMemoryPresentationChallengeStore(_clock);
        var challenge = store.IssueHosted(Guid.NewGuid(),
            "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string jwt = SignedRequest(challenge);
        var trustedBase = new Uri("https://verifier.example/oid4vp/requests/");
        var runtimeUri = new Uri(trustedBase, new string('a', 43));
        string launch = OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(
            jwt, runtimeUri, _verifier.Did, Callback, Type, Context, _clock);

        using var handler = new ProbeHandler(request =>
        {
            Assert.Equal(runtimeUri, request.RequestUri);
            Assert.Equal(HttpMethod.Get, request.Method);
            return JwtResponse(jwt);
        });
        using var http = new HttpClient(handler);
        Assert.Equal(jwt, await OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestFromTrustedBaseAsync(
            launch, trustedBase, http, _verifier.Did, Callback, Type, Context, _clock));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task PinnedBaseRejectsUntrustedHostAndSiblingPathWithoutNetwork()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string jwt = SignedRequest(challenge);
        var trustedBase = new Uri("https://verifier.example/oid4vp/requests/");
        var otherHost = new Uri("https://evil.example/oid4vp/requests/" + new string('a', 43));
        var siblingPath = new Uri("https://verifier.example/oid4vp/other/" + new string('a', 43));
        using var handler = new ProbeHandler(_ => JwtResponse(jwt));
        using var http = new HttpClient(handler);

        foreach (Uri badUri in new[] { otherHost, siblingPath })
        {
            string launch = OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(
                jwt, badUri, _verifier.Did, Callback, Type, Context, _clock);
            Assert.Null(await OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestFromTrustedBaseAsync(
                launch, trustedBase, http, _verifier.Did, Callback, Type, Context, _clock));
        }
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task PinnedBaseRejectsMalformedOpaqueReferencesAndExtraQueryBeforeNetwork()
    {
        var challenge = new InMemoryPresentationChallengeStore(_clock).IssueHosted(
            Guid.NewGuid(), "decentralized_identifier:" + _verifier.Did, _issuer.Did);
        string jwt = SignedRequest(challenge);
        var trustedBase = new Uri("https://verifier.example/oid4vp/requests/");
        var runtimeUri = new Uri(trustedBase, new string('a', 43));
        string launch = OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(
            jwt, runtimeUri, _verifier.Did, Callback, Type, Context, _clock);
        using var handler = new ProbeHandler(_ => JwtResponse(jwt));
        using var http = new HttpClient(handler);

        foreach (string bad in new[]
        {
            launch + "&request_uri=duplicate",
            launch + "#fragment",
            launch[..^1],
            launch[..^1] + "%2F",
            launch.Replace("request_uri=", "request_uri=%25", StringComparison.Ordinal),
            launch.Replace("client_id=", "client_id=evil&client_id=", StringComparison.Ordinal)
        })
        {
            Assert.Null(await OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestFromTrustedBaseAsync(
                bad, trustedBase, http, _verifier.Did, Callback, Type, Context, _clock));
        }
        Assert.Equal(0, handler.Calls);
    }

    private string HolderBoundForm(string requestJwt)
    {
        using var subject = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(new
            {
                id = _holder.Did,
                membership = "active"
            }));
        string credential = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, Type,
            Context, subject.RootElement, _issuer.Seed, _clock.GetUtcNow().AddSeconds(-5),
            _clock.GetUtcNow().AddMinutes(5));
        return OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm(
            requestJwt, _verifier.Did, Callback, Type, Context,
            credential, _holder.Did, _holder.Seed, _clock);
    }

    private string SignedRequest(PresentationChallenge challenge) =>
        OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
            challenge, _verifier.Did, _verifier.Seed, Callback, Type, Context, _clock);

    private string ByReferenceLaunch(string requestJwt) =>
        OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(requestJwt, RequestUri, _verifier.Did,
            Callback, Type, Context, _clock);

    private Task<string?> Resolve(string launch, Uri independentlyTrustedUri, HttpClient http) =>
        OpenId4VpJwtVcJsonRequestUri.FetchVerifiedRequestAsync(launch, independentlyTrustedUri, http,
            _verifier.Did, Callback, Type, Context, _clock);

    private static HttpResponseMessage JwtResponse(string request) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(request, Encoding.UTF8, "application/oauth-authz-req+jwt")
        };

    private static (byte[] Seed, string Did) Identity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }

    private sealed class Clock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }

    private sealed class NeverEndingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                .ConfigureAwait(false);
            return 0;
        }
    }

    private sealed class ProbeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            HttpResponseMessage response = respond(request);
            // Real HTTP handlers attach the executed request to the response;
            // model that metadata explicitly in this isolated in-process fake.
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

}
