using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.CredentialRevocation;

/// <summary>
/// Outcome of checking an issuer-signed, short-lived revocation snapshot.
/// NotListed is NOT a valid-credential or non-revocation certification: the
/// relying party must separately verify the credential, trust and freshness.
/// </summary>
public enum RevocationSnapshotCheckResult
{
    Invalid,
    Revoked,
    NotListed
}

/// <summary>
/// HeroSSID-specific, bounded signed revocation export (not a W3C Status List).
/// Verifiers can check it offline using an independently trusted issuer key.
/// </summary>
public static class IssuerRevocationSnapshot
{
    private const string SnapshotType = "herossid-revocation-snapshot+jwt";
    private const string CredentialType = "vc+jwt";
    private const int MaxTokenLength = 65_536;
    private const int MaxCredentialLength = 1_000_000;
    private const long MaximumLifetimeSeconds = 60;

    /// <summary>Maximum number of revoked entries in one complete snapshot.</summary>
    public const int MaximumEntries = 256;

    /// <summary>
    /// Produces a one-minute signed snapshot. Every entry must be an authentic,
    /// canonical credential signed by the supplied issuer public key.
    /// An oversized set is rejected rather than published incompletely.
    /// </summary>
    public static string Create(
        string issuerDid,
        IReadOnlyCollection<string> revokedCredentialJwts,
        byte[] issuerPrivateKey,
        byte[] issuerPublicKey,
        DateTimeOffset issuedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerDid);
        ArgumentNullException.ThrowIfNull(revokedCredentialJwts);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);

        if (issuerPrivateKey.Length != 32 || issuerPublicKey.Length != 32 ||
            revokedCredentialJwts.Count > MaximumEntries)
        {
            throw new ArgumentException("Invalid issuer keys or oversized revocation snapshot.");
        }

        var digests = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string credential in revokedCredentialJwts)
        {
            if (!StrictJwtReader.TryRead(credential, CredentialType, MaxCredentialLength, out var payload) ||
                !StrictJwtReader.TryGetString(payload, "iss", out var signedIssuer) ||
                !string.Equals(signedIssuer, issuerDid, StringComparison.Ordinal) ||
                !Ed25519JwtSigner.VerifySignedJwt(credential, issuerPublicKey))
            {
                throw new CryptographicException("Stored revoked credential has no valid issuer signature.");
            }

            digests.Add(Digest(credential));
        }

        var header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = SnapshotType });
        var payloadJson = JsonSerializer.Serialize(new
        {
            version = 1,
            iss = issuerDid,
            iat = issuedAt.ToUnixTimeSeconds(),
            exp = issuedAt.AddSeconds(MaximumLifetimeSeconds).ToUnixTimeSeconds(),
            revoked = digests.ToArray()
        });

        string token = Ed25519JwtSigner.CreateSignedJwt(header, payloadJson, issuerPrivateKey);
        if (!Ed25519JwtSigner.VerifySignedJwt(token, issuerPublicKey))
        {
            throw new CryptographicException("Issuer signing key does not match the enrolled public key.");
        }

        return token;
    }

    /// <summary>
    /// Checks a credential against a signed snapshot without server/database access.
    /// The caller MUST independently trust the issuer public key and separately
    /// validate credential claims, expiry, holder and business authorization.
    /// NotListed is deliberately not called Active or Valid.
    /// </summary>
    public static RevocationSnapshotCheckResult Check(
        string snapshotJwt,
        string credentialJwt,
        string trustedIssuerDid,
        byte[] trustedIssuerPublicKey,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshotJwt);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        if (string.IsNullOrWhiteSpace(trustedIssuerDid) ||
            trustedIssuerPublicKey is null || trustedIssuerPublicKey.Length != 32 ||
            !StrictJwtReader.TryRead(snapshotJwt, SnapshotType, MaxTokenLength, out var snapshot) ||
            !StrictJwtReader.TryRead(credentialJwt, CredentialType, MaxCredentialLength, out var credential) ||
            !Ed25519JwtSigner.VerifySignedJwt(snapshotJwt, trustedIssuerPublicKey) ||
            !Ed25519JwtSigner.VerifySignedJwt(credentialJwt, trustedIssuerPublicKey))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        try
        {
            if (!StrictJwtReader.TryGetString(snapshot, "iss", out var snapshotIssuer) ||
                !StrictJwtReader.TryGetString(credential, "iss", out var credentialIssuer) ||
                !string.Equals(snapshotIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
                !string.Equals(credentialIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
                !snapshot.TryGetProperty("version", out var version) ||
                version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber) || versionNumber != 1 ||
                !StrictJwtReader.TryGetTimestamp(snapshot, "iat", out var issued) ||
                !StrictJwtReader.TryGetTimestamp(snapshot, "exp", out var expiry) ||
                issued > now.ToUnixTimeSeconds() || expiry <= now.ToUnixTimeSeconds() ||
                expiry <= issued || expiry - issued > MaximumLifetimeSeconds ||
                !snapshot.TryGetProperty("revoked", out var revoked) || revoked.ValueKind != JsonValueKind.Array ||
                revoked.GetArrayLength() > MaximumEntries)
            {
                return RevocationSnapshotCheckResult.Invalid;
            }

            string? previous = null;
            bool found = false;
            string expectedDigest = Digest(credentialJwt);
            foreach (var entry in revoked.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String)
                {
                    return RevocationSnapshotCheckResult.Invalid;
                }

                string? value = entry.GetString();
                if (value is null || value.Length != 64 ||
                    !value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) ||
                    (previous is not null && string.CompareOrdinal(previous, value) >= 0))
                {
                    return RevocationSnapshotCheckResult.Invalid;
                }

                found |= string.Equals(value, expectedDigest, StringComparison.Ordinal);
                previous = value;
            }

            return found ? RevocationSnapshotCheckResult.Revoked : RevocationSnapshotCheckResult.NotListed;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException)
        {
            return RevocationSnapshotCheckResult.Invalid;
        }
    }

    private static string Digest(string credential) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
}
