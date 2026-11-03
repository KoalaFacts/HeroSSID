using System.Security.Cryptography;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Private, versioned purpose separation for one-use OpenID4VP request_uri
/// challenges. This marker is not part of the OpenID4VP standard and does
/// not make an HTTP Request Object durable or independently interoperable.
/// </summary>
public static class HostedPresentationChallengeNonce
{
    private static ReadOnlySpan<byte> Marker => "HSVPREQ1"u8;

    /// <summary>Whether an authentic canonical nonce carries the hosted-request purpose.</summary>
    public static bool IsHosted(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce) || !PresentationChallengePolicy.IsValidNonce(nonce))
        {
            return false;
        }

        return Base64UrlEncoder.DecodeBytes(nonce).AsSpan(0, Marker.Length)
            .SequenceEqual(Marker);
    }

    internal static string CreateNonce(bool hosted)
    {
        byte[] bytes;
        do
        {
            bytes = RandomNumberGenerator.GetBytes(32);
        }
        while (!hosted && bytes.AsSpan(0, Marker.Length).SequenceEqual(Marker));

        if (hosted)
        {
            // Reserve eight bytes for purpose/version separation; the
            // remaining 24 bytes retain 192 bits of CSPRNG entropy.
            Marker.CopyTo(bytes);
        }

        return Base64UrlEncoder.Encode(bytes);
    }
}
