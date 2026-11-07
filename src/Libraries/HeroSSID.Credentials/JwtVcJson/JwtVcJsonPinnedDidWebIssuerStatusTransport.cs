using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using HeroSSID.Core.Networking;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// The verified outcome of an exact original issuer-JWT status fetch.
/// A valid not-listed observation is not evidence of live revocation status.
/// </summary>
public sealed record JwtVcJsonIssuerStatusFetchResult(
    string SignedStatusJwt, RevocationSnapshotCheckResult Status);

/// <summary>
/// Bounded, credential-free GET of a private did:web VC1.1 exact-credential status JWT.
/// The Wallet supplies both a separately pinned issuer key and a separately approved
/// HTTPS status URI; neither is obtained from untrusted credential metadata.
/// This adapter cannot establish issuer trust, holder consent or real-world authority.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerStatusTransport
{
    private const int MaximumStatusLength = 8_192;
    private const int MaximumOriginalCredentialLength = 65_536;
    private const int MaximumUriLength = 2_048;
    private const string StatusMediaType = "application/jwt";

    /// <summary>
    /// Fetch a current issuer-signed status bound to the exact original VC1.1 JWT.
    /// A genuine revoked statement is returned as Revoked, not silently treated
    /// as success. The Wallet must still call its complete signed credential,
    /// status and challenge preflight BEFORE exposing claims or using a holder key.
    /// The supplied HttpClient MUST have an audited nonredirecting, public-only,
    /// credential-free handler; its internals cannot be inspected by this SDK.
    /// </summary>
    public static async Task<JwtVcJsonIssuerStatusFetchResult?> FetchVerifiedStatusAsync(
        Uri independentlyPinnedStatusUri, HttpClient http, string originalCredentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, TimeProvider clock,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(independentlyPinnedStatusUri);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(originalCredentialJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(clock);

        if (!IsPublicPinnedStatusUri(independentlyPinnedStatusUri) ||
            http.DefaultRequestHeaders.Any() ||
            !JwtVcJsonPinnedDidWebIssuerVerifier.IsRestrictedDidWeb(trustedIssuerDid) ||
            !(string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-1",
                StringComparison.Ordinal) ||
              string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-2",
                StringComparison.Ordinal)) ||
            independentlyPinnedIssuerPublicKey.Length != 32 ||
            independentlyPinnedIssuerPublicKey.All(static value => value == 0) ||
            string.IsNullOrWhiteSpace(originalCredentialJwt) ||
            originalCredentialJwt.Length > MaximumOriginalCredentialLength)
        {
            return null;
        }

        // Verify genuine original issuer provenance before any network access.
        // This is deliberately not a full VC policy check: issuer metadata,
        // holder, expiry, context, status and consent are gated by Wallet preflight.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (!StrictJwtReader.TryRead(originalCredentialJwt, "JWT",
                MaximumOriginalCredentialLength, out JsonElement original,
                trustedVerificationMethodId, allowMissingType: true) ||
            !Ed25519JwtSigner.VerifySignedJwt(originalCredentialJwt, pinnedKey) ||
            !StrictJwtReader.TryGetString(original, "iss", out string issuer) ||
            !string.Equals(issuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(original, "sub", out _) ||
            !StrictJwtReader.TryGetString(original, "jti", out _) ||
            !original.TryGetProperty("vc", out JsonElement vc) ||
            vc.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        TimeSpan duration = maximumDuration ?? TimeSpan.FromSeconds(15);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDuration));
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(duration);
        using var request = new HttpRequestMessage(HttpMethod.Get, independentlyPinnedStatusUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(StatusMediaType));

        try
        {
            using var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            MediaTypeHeaderValue? type = response.Content.Headers.ContentType;
            if (response.StatusCode != HttpStatusCode.OK ||
                response.RequestMessage?.RequestUri?.OriginalString !=
                    independentlyPinnedStatusUri.OriginalString ||
                type is null ||
                !string.Equals(type.MediaType, StatusMediaType,
                    StringComparison.OrdinalIgnoreCase) ||
                !AllowedCharset(type.CharSet) ||
                type.Parameters.Count > (type.CharSet is null ? 0 : 1) ||
                response.Content.Headers.ContentLength > MaximumStatusLength)
            {
                return null;
            }

            byte[] bytes = new byte[MaximumStatusLength + 1];
            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token)
                .ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int received = await stream.ReadAsync(bytes.AsMemory(length), deadline.Token)
                    .ConfigureAwait(false);
                if (received == 0)
                {
                    break;
                }

                length += received;
            }

            if (length == 0 || length > MaximumStatusLength ||
                !bytes.AsSpan(0, length).ToArray().All(
                    static value => value is >= 33 and <= 126))
            {
                return null;
            }

            string statusJwt = Encoding.ASCII.GetString(bytes, 0, length);
            RevocationSnapshotCheckResult status =
                JwtVcJsonPinnedDidWebIssuerStatus.CheckSignedStatus(
                    statusJwt, originalCredentialJwt, trustedIssuerDid,
                    trustedVerificationMethodId, pinnedKey, clock.GetUtcNow());
            return status is RevocationSnapshotCheckResult.NotListed or
                RevocationSnapshotCheckResult.Revoked
                ? new JwtVcJsonIssuerStatusFetchResult(statusJwt, status)
                : null;
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
    /// Construct a dedicated public-only transport with no redirects, cookies,
    /// proxies, ambient authentication or Activity trace propagation. DNS is
    /// resolved once and public address restrictions apply before connecting.
    /// Server TLS validation remains enabled with certificate revocation checks.
    /// </summary>
    public static SocketsHttpHandler CreateIsolatedStatusTransportHandler() => new()
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
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.Online
        }
    };

    /// <summary>
    /// Public-only safe default for wallet applications that do not supply a
    /// separately audited HttpClient. Still requires independent status URI,
    /// issuer trust pins, full-disclosure consent and holder-proof validation.
    /// </summary>
    public static async Task<JwtVcJsonIssuerStatusFetchResult?>
        FetchVerifiedStatusWithIsolatedTransportAsync(
            Uri independentlyPinnedStatusUri, string originalCredentialJwt,
            string trustedIssuerDid, string trustedVerificationMethodId,
            byte[] independentlyPinnedIssuerPublicKey, TimeProvider clock,
            TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default)
    {
        using var handler = CreateIsolatedStatusTransportHandler();
        using var http = new HttpClient(handler);
        return await FetchVerifiedStatusAsync(
            independentlyPinnedStatusUri, http, originalCredentialJwt,
            trustedIssuerDid, trustedVerificationMethodId,
            independentlyPinnedIssuerPublicKey, clock,
            maximumDuration, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsPublicPinnedStatusUri(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.HostNameType == UriHostNameType.Dns && uri.IsDefaultPort &&
        uri.UserInfo.Length == 0 && uri.Query.Length == 0 &&
        uri.Fragment.Length == 0 && uri.OriginalString.Length <= MaximumUriLength &&
        !uri.DnsSafeHost.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
        !uri.DnsSafeHost.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) &&
        !uri.DnsSafeHost.EndsWith(".local", StringComparison.OrdinalIgnoreCase) &&
        !uri.DnsSafeHost.EndsWith(".internal", StringComparison.OrdinalIgnoreCase);

    private static bool AllowedCharset(string? charset)
    {
        if (charset is null)
        {
            return true;
        }

        string normalized = charset.Length >= 2 && charset[0] == '"' &&
            charset[^1] == '"' ? charset[1..^1] : charset;
        return string.Equals(normalized, "utf-8", StringComparison.OrdinalIgnoreCase);
    }
}
