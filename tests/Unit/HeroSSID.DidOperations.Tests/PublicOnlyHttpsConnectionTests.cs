using System.Net;
using HeroSSID.Core.Networking;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// Checks the shared socket egress classifier used by opt-in pinned did:web
/// document and VC status HTTPS transports. IP policy is defence in depth:
/// it does not replace an operator's network egress controls.
/// </summary>
public sealed class PublicOnlyHttpsConnectionTests
{
    [Theory]
    [InlineData("192.0.0.1")]   // IPv4 service continuity; non-global.
    [InlineData("192.0.0.8")]   // IANA dummy address; not a destination.
    [InlineData("192.0.0.9")]   // PCP anycast; globally reachable but not an ordinary issuer.
    [InlineData("192.0.0.10")]  // TURN anycast; globally reachable but not an ordinary issuer.
    [InlineData("192.0.0.170")] // NAT64/DNS64 discovery; not a destination.
    [InlineData("192.0.0.171")] // NAT64/DNS64 discovery; not a destination.
    [InlineData("192.0.0.255")] // Unallocated in the IETF protocol assignment block.
    public void RejectsEntireIetfProtocolAssignmentBlockForIssuerHttps(string address)
    {
        Assert.False(PublicOnlyHttpsConnection.IsPublicEgressAddress(
            IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("10.3.4.5")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("192.0.2.42")]
    [InlineData("192.88.99.2")]
    [InlineData("198.18.0.1")]
    [InlineData("203.0.113.5")]
    [InlineData("2001:db8::1")]
    public void ExistingPrivateOrSpecialPurposeDenyPolicyStaysClosed(string address)
    {
        Assert.False(PublicOnlyHttpsConnection.IsPublicEgressAddress(
            IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("93.184.216.34")]
    [InlineData("192.31.196.1")] // AS112-v4 is globally reachable in IANA registry.
    [InlineData("2606:4700:4700::1111")]
    public void PublicGlobalAddressPolicyStillWorks(string address)
    {
        Assert.True(PublicOnlyHttpsConnection.IsPublicEgressAddress(
            IPAddress.Parse(address)));
    }
}
