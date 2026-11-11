using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using HeroSSID.Core.Networking;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Bounded OpenID4VP 1.0 request_uri_method=get transport for the existing
/// VC1.1 jwt_vc_json signed-request/direct_post SDK subset. This adapter does
/// not host a request_uri, obtain consent or establish wallet interoperability.
/// </summary>
public static class OpenId4VpJwtVcJsonRequestUri
{
    private const int MaximumSignedRequestBytes = 16_384;
    private const int MaximumRequestUriLength = 2_048;
    private const int MaximumInvocationLength = 4_096;
    private const string RequestObjectMediaType = "application/oauth-authz-req+jwt";

    /// <summary>
    /// Make a compact by-reference wallet launch for an already signed and
    /// valid verifier request. The operator MUST separately host the unchanged
    /// request JWT at the given HTTPS request URI. This does not create hosting.
    /// </summary>
    public static string CreateWalletInvocation(
        string requestJwt, Uri requestUri, string expectedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType,
        Uri expectedSubjectContextUri, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(requestJwt);
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);

        if (!IsAllowedRequestUri(requestUri) ||
            !OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
                requestJwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri, clock, out var signed) ||
            signed is null || !HostedPresentationChallengeNonce.IsHosted(signed.Challenge.Nonce))
        {
            throw new ArgumentException(
                "A signed, pinned verifier request and a bounded HTTPS request URI are required.",
                nameof(requestJwt));
        }

        string invocation = ExpectedInvocation(requestUri, expectedVerifierDid);
        if (invocation.Length > MaximumInvocationLength)
        {
            throw new ArgumentException("Request URI wallet invocation is too long.",
                nameof(requestUri));
        }

        return invocation;
    }

    /// <summary>
    /// Fetch the signed Request Object only from an independently trusted exact
    /// HTTPS URI, after comparing it with the canonical by-reference invocation.
    /// Requires a dedicated HttpClient with empty DefaultRequestHeaders and
    /// a credential-free handler with AllowAutoRedirect=false. Any ambient
    /// default headers fail closed before GET; a redirecting handler could send
    /// a GET elsewhere before the final-response URI check detects it.
    /// Rejects non-200/redirects, wrong media type, malformed or oversized
    /// bodies, expiry and any invalid verifier Ed25519 signature/policy.
    /// Nothing is disclosed or signed until the integrating wallet separately
    /// performs its normal authenticated VC preview and actual user consent.
    /// </summary>
    public static async Task<string?> FetchVerifiedRequestAsync(
        string invocation, Uri independentlyTrustedRequestUri, HttpClient http,
        string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(independentlyTrustedRequestUri);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);

        if (!IsAllowedRequestUri(independentlyTrustedRequestUri) ||
            string.IsNullOrWhiteSpace(expectedVerifierDid) ||
            string.IsNullOrEmpty(invocation) ||
            invocation.Length > MaximumInvocationLength ||
            !string.Equals(invocation,
                ExpectedInvocation(independentlyTrustedRequestUri, expectedVerifierDid),
                StringComparison.Ordinal))
        {
            return null;
        }

        // The public Request Object endpoint is unauthenticated. A shared
        // application HttpClient may carry bearer tokens, cookies or private
        // custom headers in its defaults; HttpClient merges these into GETs.
        // Fail closed before network access, even for a correctly pinned URI.
        // The handler must separately be non-redirecting and credential-free.
        if (http.DefaultRequestHeaders.Any())
        {
            return null;
        }

        // ResponseHeadersRead leaves content streaming outside HttpClient.Timeout.
        // A single deadline must cover both headers and the entire body, even
        // when the integrating Wallet supplies no cancellation token.
        TimeSpan duration = maximumDuration ?? TimeSpan.FromSeconds(15);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDuration));
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(duration);
        using var request = new HttpRequestMessage(HttpMethod.Get, independentlyTrustedRequestUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(RequestObjectMediaType));

        try
        {
            using var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            MediaTypeHeaderValue? contentType = response.Content.Headers.ContentType;
            if (response.StatusCode != HttpStatusCode.OK ||
                response.RequestMessage?.RequestUri?.OriginalString !=
                    independentlyTrustedRequestUri.OriginalString ||
                (contentType is null || !string.Equals(
                    contentType.MediaType, RequestObjectMediaType,
                    StringComparison.OrdinalIgnoreCase)) ||
                !IsAllowedCharset(contentType.CharSet) ||
                contentType.Parameters.Count > (contentType.CharSet is null ? 0 : 1) ||
                response.Content.Headers.ContentLength > MaximumSignedRequestBytes)
            {
                return null;
            }

            // Read no more than 16,385 bytes even if Content-Length is absent,
            // incorrect or content is transparently decompressed by the client.
            byte[] bytes = new byte[MaximumSignedRequestBytes + 1];
            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token)
                .ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(length), deadline.Token)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }

            if (length == 0 || length > MaximumSignedRequestBytes ||
                !bytes.AsSpan(0, length).ToArray().All(
                    static value => value is >= 33 and <= 126))
            {
                return null;
            }

            string jwt = Encoding.ASCII.GetString(bytes, 0, length);
            return OpenId4VpJwtVcJsonDirectPost.TryReadSignedRequest(
                jwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri, clock, out var signed) &&
                signed is not null &&
                HostedPresentationChallengeNonce.IsHosted(signed.Challenge.Nonce)
                    ? jwt : null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>
    /// Construct an isolated transport for public, unsigned-credential-free
    /// Request Object GET. No cookies, ambient credentials, Activity tracing, proxy or redirects.
    /// The caller owns and disposes this handler and must not weaken its policy.
    /// </summary>
    public static SocketsHttpHandler CreateIsolatedTransportHandler() => new()
    {
        // Request Objects are fetched from public verifier endpoints. Never send
        // the Wallet application's W3C Activity traceparent/tracestate/baggage,
        // which HttpClientHandler otherwise propagates even without default headers.
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        Credentials = null,
        DefaultProxyCredentials = null,
        PreAuthenticate = false,
        AutomaticDecompression = DecompressionMethods.None,
        ActivityHeadersPropagator = null,
        ConnectCallback = PublicOnlyHttpsConnection.ConnectAsync,
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.Online
        }
    };

    /// <summary>
    /// Fetch with a new credential-free, cookie-free, proxy-free and
    /// non-redirecting HTTP handler. Unlike the injected-client overload,
    /// this safe default cannot inherit an application's ambient handler or Activity headers.
    /// TLS server validation is not overridden. Hosts that require proxies
    /// need an explicitly audited client passed to FetchVerifiedRequestAsync.
    /// Does not grant trust to an unpinned verifier or obtain holder consent.
    /// </summary>
    public static async Task<string?> FetchVerifiedRequestWithIsolatedTransportAsync(
        string invocation, Uri independentlyTrustedRequestUri,
        string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler);
        return await FetchVerifiedRequestAsync(
            invocation, independentlyTrustedRequestUri, http,
            expectedVerifierDid, expectedResponseUri,
            expectedCredentialType, expectedSubjectContextUri,
            clock, maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolve a runtime opaque request reference under an independently pinned
    /// HTTPS base and authenticate the actual signed Request Object. This lets a
    /// Wallet follow a by-reference launch without knowing the random reference
    /// in advance. The Wallet application still owns trust enrollment, explicit
    /// full-disclosure consent and its independently audited HTTP handler.
    /// </summary>
    public static Task<string?> FetchVerifiedRequestFromTrustedBaseAsync(
        string invocation, Uri independentlyTrustedRequestBaseUri, HttpClient http,
        string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(independentlyTrustedRequestBaseUri);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);

        // The trusted static base is installed by the Wallet operator before
        // interpreting the untrusted launch. No URL authority or path is
        // selected from the launch itself; only an opaque last path segment.
        if (!IsAllowedRequestUri(independentlyTrustedRequestBaseUri) ||
            independentlyTrustedRequestBaseUri.Query.Length != 0 ||
            !independentlyTrustedRequestBaseUri.OriginalString.AsSpan().EndsWith("/", StringComparison.Ordinal) ||
            !string.Equals(independentlyTrustedRequestBaseUri.OriginalString,
                independentlyTrustedRequestBaseUri.AbsoluteUri, StringComparison.Ordinal) ||
            independentlyTrustedRequestBaseUri.OriginalString.Length + 43 > MaximumRequestUriLength ||
            string.IsNullOrWhiteSpace(expectedVerifierDid) ||
            string.IsNullOrEmpty(invocation) || invocation.Length > MaximumInvocationLength)
        {
            return Task.FromResult<string?>(null);
        }

        string prefix = "openid4vp://?client_id=" +
            Uri.EscapeDataString("decentralized_identifier:" + expectedVerifierDid) +
            "&request_uri=" + Uri.EscapeDataString(independentlyTrustedRequestBaseUri.OriginalString);
        if (!invocation.StartsWith(prefix, StringComparison.Ordinal))
        {
            return Task.FromResult<string?>(null);
        }

        string reference = invocation[prefix.Length..];
        if (reference.Length != 43 ||
            !reference.All(static character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))
        {
            return Task.FromResult<string?>(null);
        }

        // Uri performs no path traversal for a canonical base plus a base64url
        // segment. FetchVerifiedRequestAsync enforces exact URI equality,
        // credential-free defaults, bounded HTTP and the actual Ed25519 request
        // signature before releasing the unmodified signed Request Object.
        var requestUri = new Uri(independentlyTrustedRequestBaseUri, reference);
        return FetchVerifiedRequestAsync(
            invocation, requestUri, http, expectedVerifierDid, expectedResponseUri,
            expectedCredentialType, expectedSubjectContextUri, clock,
            maximumDuration, cancellationToken);
    }

    /// <summary>
    /// Resolve a launch using only a pre-trusted HTTPS base, with a new isolated
    /// transport that has no proxy, cookies, client certificate, credentials,
    /// redirects or Activity header propagation. The integrating Wallet must
    /// still pin its verifier, callback and claim vocabulary and get consent.
    /// </summary>
    public static async Task<string?> FetchVerifiedRequestFromTrustedBaseWithIsolatedTransportAsync(
        string invocation, Uri independentlyTrustedRequestBaseUri,
        string expectedVerifierDid, Uri expectedResponseUri,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler);
        return await FetchVerifiedRequestFromTrustedBaseAsync(
            invocation, independentlyTrustedRequestBaseUri, http,
            expectedVerifierDid, expectedResponseUri, expectedCredentialType,
            expectedSubjectContextUri, clock, maximumDuration,
            cancellationToken).ConfigureAwait(false);
    }

    private static bool IsAllowedCharset(string? value)
    {
        if (value is null)
        {
            return true;
        }

        // An HTTP Content-Type parameter may be a quoted-string. Preserve
        // strict UTF-8/ASCII JWT decoding while accepting RFC 9110-equivalent
        // casing and quoted charset spelling from independent verifier hosts.
        string normalized = value.Length >= 2 && value[0] == '"' && value[^1] == '"'
            ? value[1..^1] : value;
        return string.Equals(normalized, "utf-8", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExpectedInvocation(Uri requestUri, string verifierDid) =>
        "openid4vp://?client_id=" +
        Uri.EscapeDataString("decentralized_identifier:" + verifierDid) +
        "&request_uri=" + Uri.EscapeDataString(requestUri.OriginalString);

    private static bool IsAllowedRequestUri(Uri? requestUri) =>
        requestUri is { IsAbsoluteUri: true } &&
        requestUri.Scheme == Uri.UriSchemeHttps &&
        !string.IsNullOrWhiteSpace(requestUri.Host) &&
        requestUri.UserInfo.Length == 0 && requestUri.Fragment.Length == 0 &&
        requestUri.OriginalString.Length <= MaximumRequestUriLength;
}
