using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using HeroSSID.Core.Networking;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Bounded, independently pinned wallet-side HTTP delivery of an existing
/// OpenID4VP 1.0 direct_post body. The Wallet must obtain real consent and
/// generate a genuine holder-signed response BEFORE calling this transport.
/// A successful POST never proves identity, authorization or issuer status.
/// </summary>
public static class OpenId4VpJwtVcJsonWalletResponseTransport
{
    private const int MaximumFormBytes = 180_000;
    private const int MaximumResponseBytes = 4_096;
    private const string FormMediaType = "application/x-www-form-urlencoded";

    /// <summary>
    /// Send only a genuine issuer/holder Ed25519-signed, original-request-bound
    /// VP to the exact HTTPS response_uri authenticated by the original verifier
    /// Request Object and independently pinned by the Wallet.
    /// An injected HttpClient MUST use an audited handler with redirects, cookies,
    /// proxy and implicit credentials disabled; DefaultRequestHeaders are
    /// rejected, but arbitrary handler internals cannot be inspected here.
    /// Returns true only for a 200 JSON-object response from the exact endpoint.
    /// Does not interpret or follow a returned redirect_uri or prove the verifier
    /// accepted claims. The recipient must reverify issuer/holder signatures and
    /// consume the challenge atomically.
    /// </summary>
    public static async Task<bool> PostResponseFormAsync(
        string signedRequestJwt, string form, Uri independentlyTrustedResponseUri,
        HttpClient http, string expectedVerifierDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(independentlyTrustedResponseUri);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);

        // No network disclosure of a merely state-matching but arbitrary,
        // unbound, forged or differently request-bound VP. Recheck the genuine
        // verifier, issuer and holder Ed25519 signatures and exact original
        // signed Request Object hash without consuming the verifier's nonce.
        // Human full-disclosure consent remains the integrating Wallet's duty.
        if (string.IsNullOrEmpty(form) || form.Length > MaximumFormBytes ||
            http.DefaultRequestHeaders.Any() ||
            !OpenId4VpJwtVcJsonDirectPost.IsAuthenticHolderBoundWalletForm(
                signedRequestJwt, form, expectedVerifierDid,
                independentlyTrustedResponseUri, expectedCredentialType,
                expectedSubjectContextUri, clock))
        {
            return false;
        }

        // Enforce a single deadline for headers and the full (bounded) JSON
        // receipt body. A 200 is transport evidence, not a verified-credential
        // authorization decision. No untrusted redirect is ever followed here.
        TimeSpan duration = maximumDuration ?? TimeSpan.FromSeconds(15);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDuration));
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(duration);
        using var request = new HttpRequestMessage(HttpMethod.Post, independentlyTrustedResponseUri);
        request.Content = new ByteArrayContent(Encoding.ASCII.GetBytes(form));
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(FormMediaType);
        try
        {
            using var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            MediaTypeHeaderValue? contentType = response.Content.Headers.ContentType;
            if (response.StatusCode != HttpStatusCode.OK ||
                response.RequestMessage?.RequestUri?.OriginalString !=
                    independentlyTrustedResponseUri.OriginalString ||
                (contentType is null || !string.Equals(contentType.MediaType, "application/json",
                    StringComparison.OrdinalIgnoreCase)) ||
                !IsAllowedCharset(contentType.CharSet) ||
                contentType.Parameters.Count > (contentType.CharSet is null ? 0 : 1) ||
                response.Content.Headers.ContentLength > MaximumResponseBytes)
            {
                return false;
            }

            byte[] bytes = new byte[MaximumResponseBytes + 1];
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

            if (length == 0 || length > MaximumResponseBytes)
            {
                return false;
            }

            using var document = JsonDocument.Parse(bytes.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 4 });
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private static bool IsAllowedCharset(string? value)
    {
        if (value is null)
        {
            return true;
        }

        // RFC parameter values may be a quoted-string. .NET preserves the
        // surrounding quotes in MediaTypeHeaderValue.CharSet.
        string normalized = value.Length >= 2 && value[0] == '"' && value[^1] == '"'
            ? value[1..^1] : value;
        return string.Equals(normalized, "utf-8", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Dedicated direct_post handler that cannot inject cookies, redirects,
    /// ambient credentials, proxy settings or W3C Activity baggage/trace headers.
    /// Keep ordinary TLS server certificate validation and online CRL checking.
    /// </summary>
    public static SocketsHttpHandler CreateIsolatedDirectPostHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        Credentials = null,
        DefaultProxyCredentials = null,
        PreAuthenticate = false,
        AutomaticDecompression = DecompressionMethods.None,
        ActivityHeadersPropagator = null,
        ConnectCallback = PublicOnlyHttpsConnection.ConnectAsync,
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.Online
        }
    };

    /// <summary>
    /// Safe default for public verifier callbacks: a fresh disposable transport
    /// without redirects, cookies, proxies, ambient credentials or automatic
    /// client TLS certificates, and without overriding TLS server validation.
    /// An environment requiring a proxy must explicitly audit a supplied client.
    /// The method is called only AFTER the integrating Wallet obtained consent.
    /// </summary>
    public static async Task<bool> PostResponseFormWithIsolatedTransportAsync(
        string signedRequestJwt, string form, Uri independentlyTrustedResponseUri,
        string expectedVerifierDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedDirectPostHandler();
        using var http = new HttpClient(handler);
        return await PostResponseFormAsync(
            signedRequestJwt, form, independentlyTrustedResponseUri, http,
            expectedVerifierDid, expectedCredentialType, expectedSubjectContextUri,
            clock, maximumDuration, cancellationToken).ConfigureAwait(false);
    }
}
