using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.CredentialVerification;

/// <summary>
/// Result of combined offline verification of an issuer-signed credential and
/// a fresh issuer-signed revocation snapshot. No result grants business authority.
/// </summary>
public enum OfflineCredentialCheckResult
{
    Invalid,
    Revoked,
    SignedNotListed
}

/// <summary>
/// Standalone verification of the HeroSSID vc+jwt profile and its signed status
/// snapshot. The relying party must independently decide which did:key issuers
/// are trusted. No issuer database, network call or holder private key is needed.
/// </summary>
public static class OfflineCredentialVerifier
{
    private const int MaximumCredentialLength = 1_000_000;
    private const int MaximumSubjectBytes = 100_000;
    private const string ExpectedCredentialType = "vc+jwt";
    private const string DidKeyPrefix = "did:key:z";

    /// <summary>
    /// Verify the credential's real Ed25519 signature, self-certifying issuer
    /// DID, local JWT-VC structure and time validity, and signed revocation set.
    /// SignedNotListed never proves issuer registration, holder possession,
    /// real-world identity or business authorization.
    /// </summary>
    public static OfflineCredentialCheckResult Check(
        string credentialJwt, string snapshotJwt, string trustedIssuerDid, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(credentialJwt) ||
            string.IsNullOrWhiteSpace(snapshotJwt) ||
            !TryDecodeDidKeyPublicKey(trustedIssuerDid, out byte[] publicKey) ||
            !StrictJwtReader.TryRead(credentialJwt, ExpectedCredentialType, MaximumCredentialLength, out var credential) ||
            !HasValidLocalCredentialClaims(credential, trustedIssuerDid, now.ToUnixTimeSeconds()))
        {
            return OfflineCredentialCheckResult.Invalid;
        }

        // The status adjunct separately checks BOTH real Ed25519 signatures,
        // strict compact JWS representation, issuer equality, snapshot expiry,
        // sorted unique digests and the exact credential-token digest.
        return IssuerRevocationSnapshot.Check(
            snapshotJwt, credentialJwt, trustedIssuerDid, publicKey, now) switch
        {
            RevocationSnapshotCheckResult.Revoked => OfflineCredentialCheckResult.Revoked,
            RevocationSnapshotCheckResult.NotListed => OfflineCredentialCheckResult.SignedNotListed,
            _ => OfflineCredentialCheckResult.Invalid
        };
    }

    internal static bool TryDecodeDidKeyPublicKey(string? issuerDid, out byte[] publicKey)
    {
        publicKey = [];
        if (string.IsNullOrWhiteSpace(issuerDid) ||
            !issuerDid.StartsWith(DidKeyPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        string encoded = issuerDid[DidKeyPrefix.Length..];
        // Bound decoding work before accepting the caller's self-certifying key.
        if (encoded.Length is < 2 or > 128)
        {
            return false;
        }

        try
        {
            byte[] decoded = SimpleBase.Base58.Bitcoin.Decode(encoded);
            if (decoded.Length != 34 || decoded[0] != 0xed || decoded[1] != 0x01 ||
                !string.Equals(SimpleBase.Base58.Bitcoin.Encode(decoded), encoded, StringComparison.Ordinal))
            {
                return false;
            }

            publicKey = decoded.AsSpan(2).ToArray();
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException)
        {
            return false;
        }
    }

    private static bool HasValidLocalCredentialClaims(JsonElement credential, string issuerDid, long now)
    {
        if (!StrictJwtReader.TryGetString(credential, "iss", out string signedIssuer) ||
            !string.Equals(signedIssuer, issuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(credential, "sub", out string holder) ||
            holder.Length > 2048 ||
            !StrictJwtReader.TryGetTimestamp(credential, "iat", out long issuedAt) ||
            issuedAt > now)
        {
            return false;
        }

        if (credential.TryGetProperty("nbf", out _) &&
            (!StrictJwtReader.TryGetTimestamp(credential, "nbf", out long notBefore) || notBefore > now))
        {
            return false;
        }

        // The existing HeroSSID JWT profile allows missing/null expiration.
        // A supplied expiration must be a valid integer in the future.
        if (credential.TryGetProperty("exp", out var expiry) && expiry.ValueKind != JsonValueKind.Null &&
            (!StrictJwtReader.TryGetTimestamp(credential, "exp", out long expiresAt) || expiresAt <= now))
        {
            return false;
        }

        if (!credential.TryGetProperty("vc", out var vc) || vc.ValueKind != JsonValueKind.Object ||
            !vc.TryGetProperty("type", out var types) || types.ValueKind != JsonValueKind.Array ||
            !vc.TryGetProperty("credentialSubject", out var subject) || subject.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        bool hasCredentialBaseType = false;
        foreach (var type in types.EnumerateArray())
        {
            if (type.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(type.GetString()))
            {
                return false;
            }

            hasCredentialBaseType |= string.Equals(type.GetString(), "VerifiableCredential", StringComparison.Ordinal);
        }

        if (!hasCredentialBaseType || Encoding.UTF8.GetByteCount(subject.GetRawText()) > MaximumSubjectBytes)
        {
            return false;
        }

        if (subject.TryGetProperty("id", out var subjectId) &&
            (subjectId.ValueKind != JsonValueKind.String ||
             !string.Equals(subjectId.GetString(), holder, StringComparison.Ordinal)))
        {
            return false;
        }

        return true;
    }
}
