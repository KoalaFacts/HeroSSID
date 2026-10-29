using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Status of an issuer-signed direct VC2 JWT or its holder-signed presentation.
/// SignedNotListed means only that this authentic, time-bounded snapshot does not
/// contain the credential digest; it is NOT live validity or authorization.
/// </summary>
public enum Vcdm20RevocationCheckResult
{
    Invalid,
    Revoked,
    SignedNotListed
}

/// <summary>
/// Opt-in issuer-signed digest status for directly encoded VC2 JOSE credentials.
/// Uses a distinct HeroSSID-specific typ/format from legacy VC status, with no
/// database access or standard W3C Bitstring Status List claims.
/// </summary>
public static class Vcdm20RevocationSnapshot
{
    private const string SnapshotType = "herossid-vc2-revocation-snapshot+jwt";
    private const string Format = "vcdm20-direct-jose";
    private const string BaseContext = "https://www.w3.org/ns/credentials/v2";
    private const string DataPrefix = "data:application/vc+jwt,";
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumSnapshotLength = 65_536;
    private const int MaximumPresentationLength = 131_072;
    private const int MaximumSnapshotAgeSeconds = 60;
    private const int MaximumEntries = 256;

    /// <summary>
    /// Sign a COMPLETE list of issuer-revoked direct VC2 JWTs. The caller is
    /// responsible for the completeness of its authoritative status source,
    /// tenant ownership and publication; this library has no issuer database.
    /// observedAt MUST precede any external status read; signing delays shorten
    /// the snapshot lifetime, and an already stale export is refused.
    /// </summary>
    public static string Create(string issuerDid, IReadOnlyCollection<string> revokedCredentialJwts,
        byte[] issuerSeed, DateTimeOffset observedAt, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerDid);
        ArgumentNullException.ThrowIfNull(revokedCredentialJwts);
        ArgumentNullException.ThrowIfNull(issuerSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out var publicKey) ||
            issuerSeed.Length != 32 || issuerSeed.All(static b => b == 0) ||
            revokedCredentialJwts.Count > MaximumEntries)
        {
            throw new ArgumentException("Invalid self-certifying issuer, signing seed or incomplete oversized status set.");
        }

        var now = clock.GetUtcNow();
        if (observedAt.ToUnixTimeSeconds() < 0 || observedAt > now ||
            observedAt.AddSeconds(MaximumSnapshotAgeSeconds) <= now)
        {
            throw new ArgumentException("Status observation must be current and no later than signing.", nameof(observedAt));
        }

        var digests = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string credentialJwt in revokedCredentialJwts)
        {
            if (!IsAuthenticDirectVc2(credentialJwt, issuerDid, publicKey))
            {
                throw new CryptographicException("Revocation set contains a credential without valid issuer VC2 provenance.");
            }

            digests.Add(Digest(credentialJwt));
        }

        long issued = observedAt.ToUnixTimeSeconds();
        string header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = SnapshotType });
        string payload = JsonSerializer.Serialize(new
        {
            version = 1,
            iss = issuerDid,
            format = Format,
            iat = issued,
            exp = issued + MaximumSnapshotAgeSeconds,
            revoked = digests.ToArray()
        });

        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerSeed);
        if (signed.Length > MaximumSnapshotLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, publicKey))
        {
            throw new CryptographicException("Snapshot issuer signing seed does not control the claimed DID.");
        }

        // The signer may have blocked; never export a status window already elapsed.
        if (clock.GetUtcNow().ToUnixTimeSeconds() >= issued + MaximumSnapshotAgeSeconds)
        {
            throw new ArgumentException("Status snapshot expired while signing.", nameof(observedAt));
        }

        return signed;
    }

    /// <summary>
    /// Offline checks issuer authenticity and membership of one direct VC2 JWT
    /// in the issuer's bounded signed status set. Independently validate full
    /// credential policy, expiry, holder proof and business authorization.
    /// NotListed is NOT proof the issuer exported its complete revocation set.
    /// </summary>
    public static Vcdm20RevocationCheckResult Check(
        string snapshotJwt, string credentialJwt, string trustedIssuerDid, DateTimeOffset now)
    {
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var publicKey) ||
            !IsAuthenticDirectVc2(credentialJwt, trustedIssuerDid, publicKey) ||
            !StrictJwtReader.TryRead(snapshotJwt, SnapshotType, MaximumSnapshotLength, out var payload) ||
            !Ed25519JwtSigner.VerifySignedJwt(snapshotJwt, publicKey) ||
            payload.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(payload, "iss", out var issuer) ||
            !string.Equals(issuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "format", out var format) ||
            !string.Equals(format, Format, StringComparison.Ordinal) ||
            !payload.TryGetProperty("version", out var version) ||
            version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber) ||
            versionNumber != 1 ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out long issued) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out long expires) ||
            issued > now.ToUnixTimeSeconds() || expires <= now.ToUnixTimeSeconds() ||
            expires <= issued || expires - issued > MaximumSnapshotAgeSeconds ||
            !payload.TryGetProperty("revoked", out var revoked) ||
            revoked.ValueKind != JsonValueKind.Array || revoked.GetArrayLength() > MaximumEntries)
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        string expectedDigest = Digest(credentialJwt);
        string? previous = null;
        bool found = false;
        foreach (var digest in revoked.EnumerateArray())
        {
            if (digest.ValueKind != JsonValueKind.String)
            {
                return Vcdm20RevocationCheckResult.Invalid;
            }

            string? value = digest.GetString();
            if (value is null || value.Length != 64 ||
                !value.All(static c => (c is >= '0' and <= '9') || (c is >= 'a' and <= 'f')) ||
                (previous is not null && string.CompareOrdinal(previous, value) >= 0))
            {
                return Vcdm20RevocationCheckResult.Invalid;
            }

            found |= string.Equals(value, expectedDigest, StringComparison.Ordinal);
            previous = value;
        }

        return found ? Vcdm20RevocationCheckResult.Revoked :
            Vcdm20RevocationCheckResult.SignedNotListed;
    }

    /// <summary>
    /// Verify the original VC2 issuer signature, real holder control, verifier
    /// nonce, one-use challenge AND the signed status for the exact credential
    /// inside the presentation. Only the SignedNotListed result releases claims.
    /// The challenge is spent even if status subsequently rejects the proof.
    /// </summary>
    public static Vcdm20RevocationCheckResult CheckPresentation(
        string presentationJwt, string snapshotJwt, Guid tenantId, string expectedAudience,
        string expectedNonce, string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        // The issuer trust policy comes only from the verifier's own retained
        // challenge, never from an untrusted presentation or the snapshot.
        var challenge = challenges.Find(tenantId, expectedAudience, expectedNonce);
        if (challenge is null ||
            Vcdm20JosePresentation.Check(presentationJwt, tenantId, expectedAudience,
                expectedNonce, expectedCredentialType, expectedContextUri,
                challenges, clock, out var subject) != Vcdm20PresentationCheckResult.SignedButStatusUnchecked)
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        // The existing presentation checker already authenticated the holder
        // signature and exact enclosed issuer VC2. Extract that SAME token,
        // never a second caller-supplied credential that could be substituted.
        if (!TryExtractEnclosedJwt(presentationJwt, out var credentialJwt))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        var status = Check(snapshotJwt, credentialJwt, challenge.TrustedIssuerDid, clock.GetUtcNow());
        if (status == Vcdm20RevocationCheckResult.SignedNotListed)
        {
            verifiedSubject = subject;
        }

        return status;
    }

    private static bool IsAuthenticDirectVc2(string? credentialJwt, string issuerDid, byte[] issuerPublicKey)
    {
        if (!StrictJwtReader.TryRead(credentialJwt!, "vc+jwt", MaximumCredentialLength,
                out var payload, KeyId(issuerDid)) ||
            !Ed25519JwtSigner.VerifySignedJwt(credentialJwt!, issuerPublicKey) ||
            payload.EnumerateObject().Count() != 6 ||
            payload.TryGetProperty("vc", out _) || payload.TryGetProperty("vp", out _) ||
            !StrictJwtReader.TryGetString(payload, "issuer", out var signedIssuer) ||
            !string.Equals(signedIssuer, issuerDid, StringComparison.Ordinal) ||
            !HasBaseArray(payload, "@context", BaseContext) ||
            !HasBaseArray(payload, "type", "VerifiableCredential") ||
            !StrictJwtReader.TryGetString(payload, "validFrom", out _) ||
            !StrictJwtReader.TryGetString(payload, "validUntil", out _) ||
            !payload.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !StrictJwtReader.TryGetString(subject, "id", out _))
        {
            return false;
        }

        return true;
    }

    private static bool HasBaseArray(JsonElement value, string property, string expected)
    {
        if (!value.TryGetProperty(property, out var items) ||
            items.ValueKind != JsonValueKind.Array || items.GetArrayLength() != 2)
        {
            return false;
        }

        return items[0].ValueKind == JsonValueKind.String &&
            string.Equals(items[0].GetString(), expected, StringComparison.Ordinal) &&
            items[1].ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(items[1].GetString());
    }

    private static bool TryExtractEnclosedJwt(string presentationJwt, out string credentialJwt)
    {
        credentialJwt = string.Empty;
        if (!StrictJwtReader.IsCanonicalCompact(presentationJwt, MaximumPresentationLength))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                Base64UrlEncoder.DecodeBytes(presentationJwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            var payload = document.RootElement;
            if (!payload.TryGetProperty("verifiableCredential", out var entries) ||
                entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() != 1 ||
                !StrictJwtReader.TryGetString(entries[0], "id", out var uri) ||
                !uri.StartsWith(DataPrefix, StringComparison.Ordinal))
            {
                return false;
            }

            credentialJwt = uri[DataPrefix.Length..];
            return StrictJwtReader.IsCanonicalCompact(credentialJwt, MaximumCredentialLength);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static string Digest(string credential) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));

    private static string KeyId(string issuerDid) =>
        issuerDid + "#" + issuerDid["did:key:".Length..];
}
