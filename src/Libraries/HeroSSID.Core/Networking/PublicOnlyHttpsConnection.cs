using System.Net;
using System.Net.Sockets;

namespace HeroSSID.Core.Networking;

/// <summary>
/// Conservative, shared public-address HTTPS socket connector for opt-in isolated
/// outbound transports. Every resolved address must pass policy; the socket
/// connects to the vetted address without a second DNS resolution.
/// TLS hostname and certificate verification remain with SocketsHttpHandler.
/// IP filtering is not a substitute for host egress controls or trust enrollment.
/// </summary>
public static class PublicOnlyHttpsConnection
{
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

    public static async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(
                context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new HttpRequestException("Pinned HTTPS host DNS resolution failed.", ex);
        }

        // Reject *all* results on one private/special address, not merely
        // select the first public result. Connect directly to the validated
        // address: letting the default connector resolve again would reopen a
        // DNS-rebinding window between the check and the TCP connection.
        if (addresses.Length == 0 ||
            addresses.Any(static address => !IsPublicEgressAddress(address)))
        {
            throw new HttpRequestException(
                "Pinned HTTPS host resolved to a non-public or empty IP address set.");
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
            "No approved public address accepted the pinned HTTPS connection.",
            lastSocketError);
    }

}
