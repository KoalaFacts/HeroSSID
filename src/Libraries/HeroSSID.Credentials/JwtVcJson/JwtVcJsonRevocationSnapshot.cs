using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Issuer-signed, 60-second, format-specific revocation export for jwt_vc_json.
/// This private snapshot is NOT a standard W3C Bitstring Status List.
/// </summary>
public static class JwtVcJsonRevocationSnapshot
{
    private const string SnapshotType = "herossid-jwt-vc-json-revocations+jwt";
    private const string CredentialJwtType = "vc+jwt";
    private const string CredentialFormat = "jwt_vc_json";
    private const string BaseContext = "https://www.w3.org/2018/credentials/v1";
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumSnapshotLength = 65_536;
    private const int MaximumAgeSeconds = 60;

    /// <summary>Maximum number of revoked JWTs in one complete export.</summary>
    public const int MaximumEntries = 256;

    /// <summary>
    /// Sign the COMPLETE authoritative set of revoked issuer-signed VC1.1 JWTs.
    /// The issuer is responsible for tenant ownership, authoritative completeness
    /// and distribution of this private status format. Observation must occur
    /// before any external status read; signing time cannot extend freshness.
    /// </summary>
    public static string Create(string issuerDid, IReadOnlyCollection<string> revokedCredentialJwts,
        byte[] issuerSeed, DateTimeOffset observedAt, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerDid);
        ArgumentNullException.ThrowIfNull(revokedCredentialJwts);
        ArgumentNullException.ThrowIfNull(issuerSeed);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out var issuerKey) ||
            issuerSeed.Length != 32 || issuerSeed.All(static value => value == 0) ||
            revokedCredentialJwts.Count > MaximumEntries)
        {
            throw new ArgumentException("A valid issuer did:key, signing seed and complete bounded set are required.");
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (observedAt.ToUnixTimeSeconds() < 0 || observedAt > now ||
            now - observedAt >= TimeSpan.FromSeconds(MaximumAgeSeconds))
        {
            throw new ArgumentException("Revocation observation must be current and no later than signing.",
                nameof(observedAt));
        }

        var digests = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string credentialJwt in revokedCredentialJwts)
        {
            if (!IsAuthenticIssuerCredential(credentialJwt, issuerDid, issuerKey))
            {
                throw new CryptographicException(
                    "Revocation export contains a VC1.1 credential without authentic issuer provenance.");
            }

            digests.Add(Digest(credentialJwt));
        }

        long issuedAt = observedAt.ToUnixTimeSeconds();
        string header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = SnapshotType });
        string payload = JsonSerializer.Serialize(new
        {
            version = 1,
            iss = issuerDid,
            format = CredentialFormat,
            iat = issuedAt,
            exp = issuedAt + MaximumAgeSeconds,
            revoked = digests.ToArray()
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerSeed);
        if (signed.Length > MaximumSnapshotLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, issuerKey))
        {
            throw new CryptographicException("Status signer does not control the specified issuer did:key.");
        }

        if (clock.GetUtcNow().ToUnixTimeSeconds() >= issuedAt + MaximumAgeSeconds)
        {
            throw new ArgumentException("Revocation snapshot expired during signing.", nameof(observedAt));
        }

        return signed;
    }

    /// <summary>
    /// Check the issuer's signature, fresh format-specific export and exact
    /// signed JWT digest. NotListed is NOT real-time non-revocation: it assumes
    /// the issuer's externally supplied set was authoritative and complete.
    /// Separately check holder control, verifier challenge and business authority.
    /// </summary>
    public static RevocationSnapshotCheckResult Check(string snapshotJwt, string credentialJwt,
        string trustedIssuerDid, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshotJwt);
        ArgumentNullException.ThrowIfNull(credentialJwt);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var issuerKey) ||
            !IsAuthenticIssuerCredential(credentialJwt, trustedIssuerDid, issuerKey) ||
            !StrictJwtReader.TryRead(snapshotJwt, SnapshotType, MaximumSnapshotLength, out var snapshot) ||
            !Ed25519JwtSigner.VerifySignedJwt(snapshotJwt, issuerKey) ||
            snapshot.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(snapshot, "iss", out var signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(snapshot, "format", out var format) ||
            !string.Equals(format, CredentialFormat, StringComparison.Ordinal) ||
            !snapshot.TryGetProperty("version", out var version) ||
            version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var value) ||
            value != 1 ||
            !StrictJwtReader.TryGetTimestamp(snapshot, "iat", out long issuedAt) ||
            !StrictJwtReader.TryGetTimestamp(snapshot, "exp", out long expiresAt) ||
            issuedAt > now.ToUnixTimeSeconds() || expiresAt <= now.ToUnixTimeSeconds() ||
            expiresAt - issuedAt != MaximumAgeSeconds ||
            !snapshot.TryGetProperty("revoked", out var revoked) ||
            revoked.ValueKind != JsonValueKind.Array || revoked.GetArrayLength() > MaximumEntries)
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        string expected = Digest(credentialJwt);
        string? previous = null;
        bool found = false;
        foreach (var digest in revoked.EnumerateArray())
        {
            if (digest.ValueKind != JsonValueKind.String)
            {
                return RevocationSnapshotCheckResult.Invalid;
            }

            string? entry = digest.GetString();
            if (entry is null || entry.Length != 64 ||
                !entry.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                (previous is not null && string.CompareOrdinal(previous, entry) >= 0))
            {
                return RevocationSnapshotCheckResult.Invalid;
            }

            found |= string.Equals(entry, expected, StringComparison.Ordinal);
            previous = entry;
        }

        return found ? RevocationSnapshotCheckResult.Revoked : RevocationSnapshotCheckResult.NotListed;
    }

    /// <summary>
    /// Verify a real holder-signed VC1.1 VP, its unchanged issuer-signed JWT,
    /// a verifier-owned one-use challenge AND same-issuer signed status.
    /// Status is checked only against the original credential INSIDE the
    /// authenticated VP; rejected proofs never disclose subject claims.
    /// Consuming a challenge precedes the status check, so even a revoked or
    /// invalid snapshot cannot be retried under that nonce. This private status
    /// profile does not establish live non-revocation or business authority.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckPresentation(
        string presentationJwt, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string expectedCredentialType,
        Uri expectedSubjectContextUri, IPresentationChallengeStore challenges,
        TimeProvider clock, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(snapshotJwt);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId,
                expectedAudience, expectedNonce))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        var challenge = challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        if (challenge is null ||
            JwtVcJsonPresentation.Check(presentationJwt, verifierTenantId,
                expectedAudience, expectedNonce, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out var subject) !=
                JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !TryExtractEnclosedCredential(presentationJwt, out string credentialJwt))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        var status = Check(snapshotJwt, credentialJwt, challenge.TrustedIssuerDid,
            clock.GetUtcNow());
        if (status == RevocationSnapshotCheckResult.NotListed)
        {
            verifiedSubject = subject;
        }

        return status;
    }

    private static bool TryExtractEnclosedCredential(string presentationJwt,
        out string credentialJwt)
    {
        credentialJwt = string.Empty;
        if (!StrictJwtReader.IsCanonicalCompact(presentationJwt, 131_072))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                Base64UrlEncoder.DecodeBytes(presentationJwt.Split('.')[1]),
                new JsonDocumentOptions { MaxDepth = 16 });
            var payload = document.RootElement;
            if (!payload.TryGetProperty("vp", out var vp) ||
                vp.ValueKind != JsonValueKind.Object ||
                !vp.TryGetProperty("verifiableCredential", out var credentials) ||
                credentials.ValueKind != JsonValueKind.Array ||
                credentials.GetArrayLength() != 1 ||
                credentials[0].ValueKind != JsonValueKind.String)
            {
                return false;
            }

            credentialJwt = credentials[0].GetString() ?? string.Empty;
            return StrictJwtReader.IsCanonicalCompact(credentialJwt, MaximumCredentialLength);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    private static bool IsAuthenticIssuerCredential(string? jwt, string issuerDid, byte[] issuerKey)
    {
        if (!StrictJwtReader.TryRead(jwt!, CredentialJwtType, MaximumCredentialLength,
                out var payload, KeyId(issuerDid)) ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt!, issuerKey) ||
            payload.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(payload, "iss", out var issuer) ||
            !string.Equals(issuer, issuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "sub", out var holderDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out long issuedAt) ||
            !StrictJwtReader.TryGetTimestamp(payload, "nbf", out long notBefore) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out long expiresAt) ||
            notBefore != issuedAt || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 900 ||
            !payload.TryGetProperty("vc", out var vc) ||
            vc.ValueKind != JsonValueKind.Object || vc.EnumerateObject().Count() != 3 ||
            !HasBaseArray(vc, "@context", BaseContext) ||
            !HasBaseArray(vc, "type", "VerifiableCredential") ||
            !vc.TryGetProperty("credentialSubject", out var subject) ||
            subject.ValueKind != JsonValueKind.Object ||
            !StrictJwtReader.TryGetString(subject, "id", out var subjectDid) ||
            !string.Equals(subjectDid, holderDid, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    private static bool HasBaseArray(JsonElement value, string name, string baseValue)
    {
        if (!value.TryGetProperty(name, out var items) ||
            items.ValueKind != JsonValueKind.Array || items.GetArrayLength() != 2)
        {
            return false;
        }

        return items[0].ValueKind == JsonValueKind.String &&
            string.Equals(items[0].GetString(), baseValue, StringComparison.Ordinal) &&
            items[1].ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(items[1].GetString());
    }

    private static string Digest(string credentialJwt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credentialJwt)));

    private static string KeyId(string issuerDid) =>
        issuerDid + "#" + issuerDid["did:key:".Length..];
}
