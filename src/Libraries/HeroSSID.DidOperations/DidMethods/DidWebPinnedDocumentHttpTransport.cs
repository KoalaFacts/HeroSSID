using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// An opt-in, bounded HTTPS GET of a published did:web DID document, followed
/// by an exact offline match to a previously operator-pinned DID and Ed25519
/// public key. No issuer trust enrollment or private-key proof is performed.
/// </summary>
public static class DidWebPinnedDocumentHttpTransport
{
    private const int MaximumDocumentBytes = 16_384;
    private static readonly UTF8Encoding s_strictUtf8 = new(false, true);

    /// <summary>
    /// Request only the canonical HTTPS publication URI derived from a DID the
    /// integrating application has independently approved and pinned.
    /// The supplied HttpClient MUST have a dedicated credential-free handler:
    /// no automatic redirects, ambient cookies, proxies, custom credentials
    /// or Activity headers. Its handler internals cannot be inspected here;
    /// the final-response URI check alone cannot prevent intermediate redirects.
    /// Callers remain responsible for DNS/IP/SSRF policy, TLS and trusted
    /// enrollment of the DID/key (never use an untrusted claimant-supplied DID).
    /// A true result only proves a successful bounded HTTPS response matching
    /// the independently pinned one-key DID document profile. It does not prove
    /// publisher identity, key custody, authority or credential issuer trust.
    /// </summary>
    public static async Task<bool> FetchAndMatchAsync(
        string didIdentifier, byte[] expectedPublicKey, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(expectedPublicKey);
        ArgumentNullException.ThrowIfNull(http);

        if (expectedPublicKey.Length != 32 ||
            !new DidWebMethod().IsValid(didIdentifier) ||
            http.DefaultRequestHeaders.Any())
        {
            return false;
        }

        TimeSpan duration = maximumDuration ?? TimeSpan.FromSeconds(15);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDuration));
        }

        Uri exactPublicationUri = DidWebMethod.GetDocumentUri(didIdentifier);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        deadline.CancelAfter(duration);

        using var request = new HttpRequestMessage(
            HttpMethod.Get, exactPublicationUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
            "application/did+ld+json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
            "application/did+json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
            "application/json"));

        try
        {
            using var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                .ConfigureAwait(false);

            MediaTypeHeaderValue? mediaType = response.Content.Headers.ContentType;
            if (response.StatusCode != HttpStatusCode.OK ||
                response.RequestMessage?.RequestUri?.OriginalString !=
                    exactPublicationUri.OriginalString ||
                !IsAllowedContentType(mediaType) ||
                response.Content.Headers.ContentEncoding.Any() ||
                response.Content.Headers.ContentLength > MaximumDocumentBytes)
            {
                return false;
            }

            // ResponseHeadersRead does not bound the content body. Read only
            // 16,385 bytes, even for chunked responses without Content-Length.
            byte[] bytes = new byte[MaximumDocumentBytes + 1];
            using var stream = await response.Content.ReadAsStreamAsync(
                deadline.Token).ConfigureAwait(false);
            int count = 0;
            while (count < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(count),
                    deadline.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                count += read;
            }

            if (count is 0 or > MaximumDocumentBytes)
            {
                return false;
            }

            string documentJson = s_strictUtf8.GetString(bytes, 0, count);
            return DidWebPublishedKeyMatch.MatchesExpectedDocument(
                didIdentifier, expectedPublicKey, documentJson);
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A private deadline failure is not caller-initiated cancellation.
            return false;
        }
    }

    private static bool IsAllowedContentType(MediaTypeHeaderValue? value)
    {
        if (value is null ||
            (!string.Equals(value.MediaType, "application/did+ld+json",
                StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(value.MediaType, "application/did+json",
                StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(value.MediaType, "application/json",
                StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        string? charset = value.CharSet;
        if (charset is null)
        {
            return value.Parameters.Count == 0;
        }

        // HttpHeaders may retain quotes around a valid RFC charset token.
        string normalized = charset.Length >= 2 && charset[0] == '"' &&
            charset[^1] == '"' ? charset[1..^1] : charset;
        return string.Equals(normalized, "utf-8",
            StringComparison.OrdinalIgnoreCase) && value.Parameters.Count == 1;
    }

    /// <summary>
    /// Build a disposable default handler for a preapproved did:web HTTPS host.
    /// This rejects automatic redirects, proxy/cookie/credential attachment and
    /// Activity tracing; normal TLS certificate validation is retained.
    /// Domain resolution and network segmentation remain the operator's task.
    /// </summary>
    public static SocketsHttpHandler CreateIsolatedTransportHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        Credentials = null,
        DefaultProxyCredentials = null,
        PreAuthenticate = false,
        AutomaticDecompression = DecompressionMethods.None,
        ActivityHeadersPropagator = null,
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.Online
        }
    };

    /// <summary>
    /// Fetch using an ephemeral credential-free and non-redirecting handler,
    /// after the integrating application has independently pinned DID and key.
    /// Never call with a DID drawn from an untrusted remote request.
    /// </summary>
    public static async Task<bool> FetchAndMatchWithIsolatedTransportAsync(
        string didIdentifier, byte[] expectedPublicKey,
        TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler, disposeHandler: false);
        return await FetchAndMatchAsync(
            didIdentifier, expectedPublicKey, http, maximumDuration,
            cancellationToken).ConfigureAwait(false);
    }
}
