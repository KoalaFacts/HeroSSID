using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Private HeroSSID 60-second original-JWT status for a separately pinned did:web
/// issuer. This is NOT the W3C Bitstring Status List format or live revocation.
/// It does not prove holder control, legal identity or business authority.
/// </summary>
public static class Vcdm20PinnedDidWebIssuerStatus
{
    private const string SnapshotType = "herossid-vc2-revocation-snapshot+jwt";
    private const string Format = "vcdm20-direct-jose";
    private const int MaximumJwtLength = 65_536;
    private const int MaximumEntries = 256;
    private const int MaximumAgeSeconds = 60;

    /// <summary>
    /// Sign an issuer-owned complete set of currently known revoked ORIGINAL
    /// VC2 JWTs. All listed JWTs must have the actual same did:web signer.
    /// The caller owns authoritative status collection, seed custody, and the
    /// observation instant recorded BEFORE collecting the status set.
    /// </summary>
    public static string Create(
        string issuerDid, string assertionMethodId, byte[] issuerSeed,
        byte[] issuerPublicKey, string issuerName,
        IReadOnlyCollection<string> revokedCredentialJwts,
        DateTimeOffset observedAt, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(issuerSeed);
        ArgumentNullException.ThrowIfNull(revokedCredentialJwts);
        ArgumentNullException.ThrowIfNull(clock);
        if (!ValidPinnedIssuer(issuerDid, assertionMethodId, issuerPublicKey) ||
            string.IsNullOrWhiteSpace(issuerName) ||
            issuerSeed.Length != 32 || issuerSeed.All(static value => value == 0) ||
            revokedCredentialJwts.Count > MaximumEntries)
        {
            throw new ArgumentException("An enrolled did:web signer and bounded authoritative revocation set are required.");
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (observedAt < DateTimeOffset.UnixEpoch || observedAt > now ||
            observedAt.AddSeconds(MaximumAgeSeconds) <= now)
        {
            throw new ArgumentException("An authentic, current pre-read observation instant is required.", nameof(observedAt));
        }

        var digests = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string jwt in revokedCredentialJwts)
        {
            if (!IsAuthenticIssuerCredential(jwt, issuerDid, assertionMethodId,
                    issuerPublicKey, issuerName))
            {
                throw new CryptographicException(
                    "The revocation set includes a JWT without authentic same-key did:web VC2 provenance.");
            }

            digests.Add(Digest(jwt));
        }

        long issuedAt = observedAt.ToUnixTimeSeconds();
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = SnapshotType
        });
        string payload = JsonSerializer.Serialize(new
        {
            version = 1,
            iss = issuerDid,
            format = Format,
            iat = issuedAt,
            exp = issuedAt + MaximumAgeSeconds,
            revoked = digests.ToArray()
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerSeed);
        if (signed.Length > MaximumJwtLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, issuerPublicKey))
        {
            throw new CryptographicException(
                "Status signing key does not control the independently approved did:web public key.");
        }

        if (clock.GetUtcNow().ToUnixTimeSeconds() >= issuedAt + MaximumAgeSeconds)
        {
            throw new ArgumentException("The status expired while signing.", nameof(observedAt));
        }

        return signed;
    }

    /// <summary>
    /// Verify genuine same-issuer status for an independently pinned, still-live
    /// did:web VC2 credential. Only a fresh, signed, exact-JWT non-listed status
    /// releases issuer-authenticated subject claims. Revoked, forged, stale or
    /// mismatched status releases nothing. SignedNotListed is not proof of a
    /// complete or live status feed, holder key control or authorization.
    /// </summary>
    public static Vcdm20RevocationCheckResult Check(
        string snapshotJwt, string credentialJwt,
        string trustedIssuerDid, string trustedAssertionMethodId,
        byte[] pinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, Uri expectedAudience, string expectedHolderDid,
        string expectedCredentialType, Uri expectedContextUri,
        DateTimeOffset minimumObservedAtUtc, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        if (string.IsNullOrWhiteSpace(snapshotJwt) ||
            string.IsNullOrWhiteSpace(credentialJwt) ||
            !ValidPinnedIssuer(trustedIssuerDid, trustedAssertionMethodId, pinnedIssuerPublicKey) ||
            minimumObservedAtUtc < DateTimeOffset.UnixEpoch ||
            minimumObservedAtUtc > now ||
            !Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
                credentialJwt, trustedIssuerDid, trustedAssertionMethodId,
                pinnedIssuerPublicKey, expectedIssuerName, expectedCredentialId,
                expectedAudience, expectedHolderDid, expectedCredentialType,
                expectedContextUri, now, out JsonElement authenticatedSubject) ||
            !StrictJwtReader.TryRead(snapshotJwt, SnapshotType, MaximumJwtLength,
                out JsonElement payload) ||
            !Ed25519JwtSigner.VerifySignedJwt(snapshotJwt, pinnedIssuerPublicKey) ||
            payload.EnumerateObject().Count() != 6 ||
            !payload.TryGetProperty("version", out JsonElement version) ||
            version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out int versionNumber) || versionNumber != 1 ||
            !StrictJwtReader.TryGetString(payload, "iss", out string signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "format", out string format) ||
            !string.Equals(format, Format, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out long issuedAt) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out long expiresAt) ||
            issuedAt < 0 || issuedAt > now.ToUnixTimeSeconds() ||
            expiresAt <= now.ToUnixTimeSeconds() ||
            expiresAt <= issuedAt || expiresAt - issuedAt > MaximumAgeSeconds ||
            DateTimeOffset.FromUnixTimeSeconds(issuedAt) < minimumObservedAtUtc ||
            !payload.TryGetProperty("revoked", out JsonElement revoked) ||
            revoked.ValueKind != JsonValueKind.Array ||
            revoked.GetArrayLength() > MaximumEntries)
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        string digest = Digest(credentialJwt);
        string? previous = null;
        bool found = false;
        foreach (JsonElement element in revoked.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                return Vcdm20RevocationCheckResult.Invalid;
            }

            string? current = element.GetString();
            if (current is null || current.Length != 64 ||
                !current.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                (previous is not null && string.CompareOrdinal(previous, current) >= 0))
            {
                return Vcdm20RevocationCheckResult.Invalid;
            }

            found |= string.Equals(digest, current, StringComparison.Ordinal);
            previous = current;
        }

        if (found)
        {
            return Vcdm20RevocationCheckResult.Revoked;
        }

        verifiedSubject = authenticatedSubject;
        return Vcdm20RevocationCheckResult.SignedNotListed;
    }

    private static bool IsAuthenticIssuerCredential(
        string? jwt, string issuerDid, string method, byte[] publicKey, string issuerName)
    {
        if (string.IsNullOrWhiteSpace(jwt) ||
            !StrictJwtReader.TryRead(jwt, "vc+jwt", MaximumJwtLength,
                out JsonElement payload, method, "vc") ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, publicKey) ||
            payload.EnumerateObject().Count() != 8 ||
            !payload.TryGetProperty("issuer", out JsonElement descriptor) ||
            descriptor.ValueKind != JsonValueKind.Object ||
            descriptor.EnumerateObject().Count() != 2 ||
            !StrictJwtReader.TryGetString(descriptor, "id", out string signedDid) ||
            !string.Equals(signedDid, issuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(descriptor, "name", out string signedName) ||
            !string.Equals(signedName, issuerName, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "id", out string signedId) ||
            !Uri.TryCreate(signedId, UriKind.Absolute, out Uri? id) ||
            !StrictJwtReader.TryGetString(payload, "aud", out string signedAudience) ||
            !Uri.TryCreate(signedAudience, UriKind.Absolute, out Uri? audience) ||
            !SecondString(payload, "@context",
                "https://www.w3.org/ns/credentials/v2", out string context) ||
            !Uri.TryCreate(context, UriKind.Absolute, out Uri? subjectContext) ||
            !SecondString(payload, "type", "VerifiableCredential", out string credentialType) ||
            !payload.TryGetProperty("credentialSubject", out JsonElement subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !StrictJwtReader.TryGetString(subject, "id", out string holderDid) ||
            !StrictJwtReader.TryGetString(payload, "validFrom", out string validFrom) ||
            !DateTimeOffset.TryParse(validFrom, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset firstValid))
        {
            return false;
        }

        // These signed fields are used only to authenticate an issuer-owned
        // revocation inventory. The relying verifier MUST separately pin all
        // of them through Check; it never learns its policy from this JWT.
        return Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
            jwt, issuerDid, method, publicKey, issuerName, id, audience,
            holderDid, credentialType, subjectContext, firstValid, out _);
    }

    private static bool SecondString(
        JsonElement payload, string name, string first, out string second)
    {
        second = string.Empty;
        if (!payload.TryGetProperty(name, out JsonElement items) ||
            items.ValueKind != JsonValueKind.Array ||
            items.GetArrayLength() != 2 ||
            items[0].ValueKind != JsonValueKind.String ||
            !string.Equals(items[0].GetString(), first, StringComparison.Ordinal) ||
            items[1].ValueKind != JsonValueKind.String)
        {
            return false;
        }

        second = items[1].GetString()!;
        return !string.IsNullOrWhiteSpace(second);
    }

    private static bool ValidPinnedIssuer(
        string? issuerDid, string? method, byte[]? publicKey) =>
        !string.IsNullOrWhiteSpace(issuerDid) &&
        JwtVcJsonPinnedDidWebIssuerVerifier.IsRestrictedDidWeb(issuerDid) &&
        (string.Equals(method, issuerDid + "#key-1", StringComparison.Ordinal) ||
         string.Equals(method, issuerDid + "#key-2", StringComparison.Ordinal)) &&
        publicKey is { Length: 32 } &&
        !publicKey.All(static value => value == 0);

    private static string Digest(string jwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(jwt)));
}
