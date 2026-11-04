using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Net.Sockets;
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

        return await FetchAndMatchDocumentAsync(didIdentifier, http,
            json => DidWebPublishedKeyMatch.MatchesExpectedDocument(
                didIdentifier, expectedPublicKey, json),
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieve an exact two-key overlap document for an independently pinned
    /// DID and BOTH preapproved Ed25519 keys. The supplied HttpClient must
    /// have a credential-free non-redirecting handler. This verifies only a
    /// document shape, not private-key custody, authority or issuer trust.
    /// </summary>
    public static async Task<bool> FetchAndMatchTransitionAsync(
        string didIdentifier, byte[] pinnedOldPublicKey, byte[] pinnedNewPublicKey,
        HttpClient http, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(pinnedOldPublicKey);
        ArgumentNullException.ThrowIfNull(pinnedNewPublicKey);
        ArgumentNullException.ThrowIfNull(http);

        if (!new DidWebMethod().IsValid(didIdentifier) ||
            pinnedOldPublicKey.Length != 32 || pinnedNewPublicKey.Length != 32 ||
            CryptographicOperations.FixedTimeEquals(
                pinnedOldPublicKey, pinnedNewPublicKey) ||
            http.DefaultRequestHeaders.Any())
        {
            return false;
        }

        return await FetchAndMatchDocumentAsync(didIdentifier, http,
            json => DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
                didIdentifier, pinnedOldPublicKey, pinnedNewPublicKey, json),
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetch a preapproved two-key overlap DID using a disposable isolated
    /// HTTPS handler. Network egress and independent trust policy remain the
    /// operator's responsibility; the successor is not promoted to trust.
    /// </summary>
    public static async Task<bool> FetchAndMatchTransitionWithIsolatedTransportAsync(
        string didIdentifier, byte[] pinnedOldPublicKey, byte[] pinnedNewPublicKey,
        TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedTransportHandler();
        using var http = new HttpClient(handler, disposeHandler: false);
        return await FetchAndMatchTransitionAsync(
            didIdentifier, pinnedOldPublicKey, pinnedNewPublicKey, http,
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    // Shared fail-closed response path for single-key and two-key profiles.
    internal static async Task<bool> FetchAndMatchDocumentAsync(
        string didIdentifier, HttpClient http, Func<string, bool> matches,
        TimeSpan? maximumDuration, CancellationToken cancellationToken)
    {
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
                response.Content.Headers.ContentEncoding.Count != 0 ||
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
            return matches(documentJson);
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
    /// DNS addresses are rechecked at socket connection time against a
    /// conservative public-only egress policy (mixed private/public responses
    /// fail closed). The operator still owns network egress controls.
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
        ConnectCallback = ConnectPublicOnlyAsync,
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.Online
        }
    };


    /// <summary>
    /// Conservative public-only IP filter used by the isolated HTTPS transport
    /// at connect time. It rejects loopback, private, shared, link-local,
    /// documentation, benchmark and transition addresses. A permitted address
    /// is not proof of safe network routing, domain ownership or issuer trust.
    /// </summary>
    public static bool IsPublicEgressAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] is not (0 or 10 or 127 or >= 224) &&
                !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127) &&
                !(bytes[0] == 169 && bytes[1] == 254) &&
                !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
                !(bytes[0] == 192 && bytes[1] == 168) &&
                !(bytes[0] == 192 && bytes[1] == 0 &&
                    bytes[2] is 0 or 2) &&
                !(bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99) &&
                !(bytes[0] == 198 && bytes[1] is 18 or 19) &&
                !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) &&
                !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6 ||
            address.IsIPv4MappedToIPv6 ||
            (bytes[0] & 0xe0) != 0x20)
        {
            // Only native global-unicast 2000::/3 may be considered.
            return false;
        }

        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            return false; // 6to4 IPv4 tunnel destinations.
        }

        if (bytes[0] == 0x3f && bytes[1] == 0xff &&
            (bytes[2] & 0xf0) == 0x00)
        {
            return false; // RFC 9637 documentation prefix 3fff::/20.
        }

        if (bytes[0] == 0x20 && bytes[1] == 0x01 &&
            (bytes[2] & 0xfe) == 0)
        {
            // IANA's IETF protocol assignment 2001::/23 is non-global by
            // default. Even its more-specific public exceptions are rejected
            // here: this conservative HTTPS fetch must not silently adopt
            // new protocol allocations as ordinary issuer destinations.
            return false;
        }

        return !(bytes[0] == 0x20 && bytes[1] == 0x01 &&
            bytes[2] == 0x0d && bytes[3] == 0xb8); // Documentation.
    }

    private static async ValueTask<Stream> ConnectPublicOnlyAsync(
        SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(
                context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new HttpRequestException("Pinned DID host DNS resolution failed.", ex);
        }

        // Reject *all* results on one private/special address, not merely
        // select the first public result. Connect directly to the validated
        // address: letting the default connector resolve again would reopen a
        // DNS-rebinding window between the check and the TCP connection.
        if (addresses.Length == 0 ||
            addresses.Any(static address => !IsPublicEgressAddress(address)))
        {
            throw new HttpRequestException(
                "Pinned DID host resolved to a non-public or empty IP address set.");
        }

        SocketException? lastSocketError = null;
        foreach (IPAddress address in addresses)
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(address.AddressFamily,
                    SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(address, context.DnsEndPoint.Port,
                    cancellationToken).ConfigureAwait(false);
                var stream = new NetworkStream(socket, ownsSocket: true);
                socket = null; // The returned stream now owns the connected socket.
                return stream;
            }
            catch (SocketException ex)
            {
                lastSocketError = ex;
            }
            finally
            {
                socket?.Dispose(); // Failure and cancellation paths own the socket.
            }
        }

        throw new HttpRequestException(
            "No approved public address accepted the pinned DID HTTPS connection.",
            lastSocketError);
    }

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
