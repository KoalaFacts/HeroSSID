using System.Net;
using System.Net.Http.Headers;
using System.Text;

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
                expectedCredentialType, expectedSubjectContextUri, clock, out _))
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
    /// Requires a dedicated, unauthenticated HttpClient whose handler has
    /// AllowAutoRedirect=false; a caller-supplied redirecting client could send
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
                contentType?.MediaType != RequestObjectMediaType ||
                (contentType.CharSet is not null &&
                    !string.Equals(contentType.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase)) ||
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
                expectedCredentialType, expectedSubjectContextUri, clock, out _)
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
