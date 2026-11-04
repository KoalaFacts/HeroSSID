using System.Net;
using System.Net.Sockets;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Tests;

public sealed class OpenId4VpWalletPublicEgressTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IsolatedWalletHandlerMustEnforceAddressPolicyAtSocketConnect(bool directPost)
    {
        using SocketsHttpHandler handler = CreateHandler(directPost);
        // A mere HTTPS URI pin is insufficient when DNS is rebound to a
        // loopback, link-local or private endpoint after the app approved it.
        Assert.NotNull(handler.ConnectCallback);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IsolatedWalletHandlerNeverConnectsToLoopbackBeforeTls(bool directPost)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using SocketsHttpHandler handler = CreateHandler(directPost);
            using var http = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(2)
            };
            var target = new Uri($"https://127.0.0.1:{port}/wallet-private-probe");
            // Exercise the real SocketsHttpHandler connector, not a mocked
            // HttpMessageHandler. TLS must never start because TCP must never
            // reach a local service, even if its certificate would be rejected.
            try
            {
                using HttpResponseMessage response = await http.GetAsync(
                    target);
            }
            catch (HttpRequestException)
            {
                // Expected: the egress policy refuses the socket.
            }
            catch (TaskCanceledException)
            {
                // Before the fix an untrusted private TLS socket can stall.
            }

            Assert.False(listener.Pending());
        }
        finally
        {
            listener.Stop();
        }
    }

    private static SocketsHttpHandler CreateHandler(bool directPost) =>
        directPost
            ? OpenId4VpJwtVcJsonWalletResponseTransport.CreateIsolatedDirectPostHandler()
            : OpenId4VpJwtVcJsonRequestUri.CreateIsolatedTransportHandler();
}
