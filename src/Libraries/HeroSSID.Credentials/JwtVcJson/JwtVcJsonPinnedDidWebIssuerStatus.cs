using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Opt-in exact-credential issuer-signed status for a separately pinned did:web issuer.
/// This private status envelope is not a W3C status-list or interoperability profile.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerStatus
{
    private const string StatusType = "herossid-didweb-vc11-exact-status+jwt";
    private const int MaximumStatusLength = 8_192;
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumAgeSeconds = 60;

    /// <summary>
    /// Sign one issuer-observed revoked/not-revoked statement over the original compact VC JWT.
    /// The caller independently owns issuer key custody and the authoritative status record.
    /// The signer must control the same separately pinned assertion method as the credential.
    /// </summary>
    public static string Create(
        string originalCredentialJwt, string issuerDid, string assertionMethodId,
        byte[] independentlyPinnedIssuerPublicKey, byte[] issuerSeed,
        bool revoked, DateTimeOffset observedAt, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(originalCredentialJwt);
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(assertionMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(issuerSeed);
        ArgumentNullException.ThrowIfNull(clock);

        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (!ValidIssuerPin(issuerDid, assertionMethodId, pinnedKey) ||
            issuerSeed.Length != 32 || issuerSeed.All(static b => b == 0))
        {
            throw new ArgumentException("A restricted did:web issuer, separately pinned key and private signing seed are required.");
        }

        // A status issuer cannot use this SDK to sign a statement over an
        // attacker-supplied unsigned/foreign original credential.
        if (!StrictJwtReader.TryRead(originalCredentialJwt, "JWT",
                MaximumCredentialLength, out JsonElement credential,
                assertionMethodId, allowMissingType: true) ||
            !Ed25519JwtSigner.VerifySignedJwt(originalCredentialJwt, pinnedKey) ||
            !StrictJwtReader.TryGetString(credential, "iss", out string signedIssuer) ||
            !string.Equals(signedIssuer, issuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(credential, "sub", out _) ||
            !StrictJwtReader.TryGetString(credential, "jti", out _) ||
            !credential.TryGetProperty("vc", out JsonElement vc) ||
            vc.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException(
                "The status subject must be an original issuer-signed VC1.1 JWT from this exact method.",
                nameof(originalCredentialJwt));
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (observedAt < DateTimeOffset.UnixEpoch || observedAt > now ||
            now >= observedAt.AddSeconds(MaximumAgeSeconds))
        {
            throw new ArgumentException("Status observation must be genuine, current and no later than signing.",
                nameof(observedAt));
        }

        decimal observedSeconds = NumericDate(observedAt);
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = StatusType,
            kid = assertionMethodId
        });
        string payload = JsonSerializer.Serialize(new
        {
            version = 1,
            iss = issuerDid,
            sha256 = Digest(originalCredentialJwt),
            revoked,
            iat = observedSeconds,
            exp = observedSeconds + MaximumAgeSeconds
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerSeed);

        // The private seed's association with the pinned public key is not
        // inferred from the supplied DID, header or caller's assertion.
        RevocationSnapshotCheckResult expected = revoked
            ? RevocationSnapshotCheckResult.Revoked
            : RevocationSnapshotCheckResult.NotListed;
        if (signed.Length > MaximumStatusLength ||
            CheckSignedStatus(signed, originalCredentialJwt, issuerDid,
                assertionMethodId, pinnedKey, clock.GetUtcNow()) != expected)
        {
            throw new CryptographicException(
                "Issuer status signature is not controlled by the independently pinned assertion key.");
        }

        return signed;
    }

    /// <summary>
    /// Authenticate the original issuer/holder signatures and one-use verifier challenge,
    /// then gate disclosure on a fresh genuine issuer status for that exact credential.
    /// A genuine proof spends its challenge even when status is revoked, stale, forged or
    /// for another credential. Empty/oversized status fails before challenge consumption.
    /// </summary>
    public static RevocationSnapshotCheckResult CheckPresentation(
        string presentationJwt, string statusJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(statusJwt);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        // Missing status is a missing verifier prerequisite, not a reason to
        // spend a genuine holder's pending request. Malformed signed status is
        // evaluated after an otherwise authentic one-use presentation is spent.
        if (string.IsNullOrWhiteSpace(statusJwt) ||
            statusJwt.Length > MaximumStatusLength)
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        if (!ValidIssuerPin(trustedIssuerDid, trustedVerificationMethodId, pinnedKey) ||
            JwtVcJsonPinnedDidWebIssuerPresentation.Check(
                presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
                trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
                expectedIssuerName, expectedCredentialId, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out JsonElement subject) !=
                JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !JwtVcJsonPinnedDidWebPresentationDenylist.TryGetExactOriginalCredential(
                presentationJwt, out string originalCredentialJwt))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        RevocationSnapshotCheckResult status = CheckSignedStatus(
            statusJwt, originalCredentialJwt, trustedIssuerDid,
            trustedVerificationMethodId, pinnedKey, clock.GetUtcNow());
        if (status == RevocationSnapshotCheckResult.NotListed)
        {
            verifiedSubject = subject;
        }

        return status;
    }

    // Internal only: caller must first authenticate and atomically consume a real holder VP.
    internal static RevocationSnapshotCheckResult CheckSignedStatus(
        string statusJwt, string originalCredentialJwt, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] pinnedKey, DateTimeOffset now)
    {
        if (!StrictJwtReader.TryRead(statusJwt, StatusType,
                MaximumStatusLength, out JsonElement claims, trustedVerificationMethodId) ||
            !Ed25519JwtSigner.VerifySignedJwt(statusJwt, pinnedKey) ||
            claims.EnumerateObject().Count() != 6 ||
            !claims.TryGetProperty("version", out JsonElement version) ||
            version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out int v) || v != 1 ||
            !StrictJwtReader.TryGetString(claims, "iss", out string signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(claims, "sha256", out string signedDigest) ||
            !string.Equals(signedDigest, Digest(originalCredentialJwt), StringComparison.Ordinal) ||
            !claims.TryGetProperty("revoked", out JsonElement revoked) ||
            revoked.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            !JwtVcJsonCredential.TryGetSignedNumericDate(
                claims, "iat", normative: true, out decimal observedSeconds) ||
            !JwtVcJsonCredential.TryGetSignedNumericDate(
                claims, "exp", normative: true, out decimal expiresSeconds))
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        decimal nowSeconds = NumericDate(now);
        if (observedSeconds > nowSeconds || expiresSeconds <= nowSeconds ||
            expiresSeconds - observedSeconds != MaximumAgeSeconds)
        {
            return RevocationSnapshotCheckResult.Invalid;
        }

        return revoked.ValueKind == JsonValueKind.True
            ? RevocationSnapshotCheckResult.Revoked
            : RevocationSnapshotCheckResult.NotListed;
    }

    private static bool ValidIssuerPin(string issuerDid, string method,
        byte[] key) =>
        JwtVcJsonPinnedDidWebIssuerVerifier.IsRestrictedDidWeb(issuerDid) &&
        (string.Equals(method, issuerDid + "#key-1", StringComparison.Ordinal) ||
         string.Equals(method, issuerDid + "#key-2", StringComparison.Ordinal)) &&
        key.Length == 32 && key.Any(static b => b != 0);

    private static decimal NumericDate(DateTimeOffset instant) =>
        (decimal)(instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) /
        TimeSpan.TicksPerSecond;

    private static string Digest(string originalJwt) =>
        Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(originalJwt)));
}
