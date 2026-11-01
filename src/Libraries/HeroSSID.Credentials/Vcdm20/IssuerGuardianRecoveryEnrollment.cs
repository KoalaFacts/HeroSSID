using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// An old issuer key can pre-sign the exact guardian roster and quorum to be
/// used after that key is lost. Recovery requires a verifier-owned SHA-256 pin
/// of this exact enrollment JWT, recorded through a separate trusted channel
/// before the incident. This private format is not DID rotation or authority.
/// </summary>
public static class IssuerGuardianRecoveryEnrollment
{
    private const string HeaderType = "herossid-issuer-guardian-enrollment+jwt";
    private const string Purpose = "issuer-guardian-preenrollment";
    private const int MaximumJwtLength = 4_096;
    private const decimal MaximumLifetimeSeconds = 365m * 24m * 60m * 60m;

    /// <summary>
    /// Pre-sign an exact old-issuer guardian policy. The caller must store the
    /// exact resulting JWT and separately approve/pin its SHA-256 fingerprint
    /// BEFORE loss or compromise of the old issuer key. Private key ownership
    /// and clearing remain the issuer application's responsibility.
    /// </summary>
    public static string Create(string previousIssuerDid, byte[] previousIssuerSeed,
        IReadOnlyCollection<string> guardianDids, int requiredGuardianSignatures,
        Uri verifierAudience, DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        ArgumentNullException.ThrowIfNull(previousIssuerDid);
        ArgumentNullException.ThrowIfNull(previousIssuerSeed);
        ArgumentNullException.ThrowIfNull(guardianDids);
        ArgumentNullException.ThrowIfNull(verifierAudience);

        decimal issued = PresentationChallengePolicy.NumericDate(validFrom);
        decimal expires = PresentationChallengePolicy.NumericDate(validUntil);
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(previousIssuerDid, out _) ||
            previousIssuerSeed.Length != 32 ||
            previousIssuerSeed.All(static b => b == 0) ||
            !ValidAudience(verifierAudience) ||
            !TryValidatePins(previousIssuerDid, guardianDids, requiredGuardianSignatures,
                out string[] ordered) ||
            issued < 0m || expires >= 253402300800m || expires <= issued ||
            expires - issued > MaximumLifetimeSeconds)
        {
            throw new ArgumentException("A genuine old issuer key, distinct guardian quorum, HTTPS audience and bounded enrollment period are required.");
        }

        string payload = JsonSerializer.Serialize(new
        {
            version = 1,
            purpose = Purpose,
            previousIssuer = previousIssuerDid,
            aud = verifierAudience.AbsoluteUri,
            guardianDids = ordered,
            requiredSignatures = requiredGuardianSignatures,
            iat = issued,
            exp = expires
        });
        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = HeaderType,
            kid = KeyId(previousIssuerDid)
        });
        string jwt = Ed25519JwtSigner.CreateSignedJwt(header, payload, previousIssuerSeed);

        // Confirm the actual Ed25519 seed matches the pinned old DID before
        // releasing an artifact that might be stored as recovery policy.
        if (jwt.Length > MaximumJwtLength ||
            !TryVerify(jwt, previousIssuerDid, Fingerprint(jwt),
                verifierAudience, validFrom, out _, out _))
        {
            throw new ArgumentException("The old issuer seed does not authenticate its own did:key.", nameof(previousIssuerSeed));
        }

        return jwt;
    }

    /// <summary>
    /// Return the uppercase SHA-256 of the exact compact JWT bytes.
    /// Computing a fingerprint does NOT approve it: the verifier must pin
    /// this exact value independently before an issuer-key-loss incident.
    /// </summary>
    public static string Fingerprint(string signedEnrollmentJwt)
    {
        ArgumentNullException.ThrowIfNull(signedEnrollmentJwt);
        if (signedEnrollmentJwt.Length is 0 or > MaximumJwtLength)
        {
            throw new ArgumentException("Enrollment JWT is outside the supported bounds.", nameof(signedEnrollmentJwt));
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(signedEnrollmentJwt)));
    }

    /// <summary>
    /// Validate a genuine old-issuer Ed25519 signature, exact independently
    /// approved enrollment digest, audience, guardian roster, quorum and UTC
    /// validity. No guardian policy is disclosed on failure. In particular,
    /// an arbitrary old-key-signed JWT without a pre-incident digest pin is
    /// not independent proof that the organization enrolled those guardians.
    /// </summary>
    public static bool TryVerify(string signedEnrollmentJwt, string trustedPreviousIssuerDid,
        string independentlyPinnedSha256, Uri verifierAudience, DateTimeOffset now,
        out string[] guardianDids, out int requiredGuardianSignatures)
    {
        ArgumentNullException.ThrowIfNull(signedEnrollmentJwt);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(independentlyPinnedSha256);
        ArgumentNullException.ThrowIfNull(verifierAudience);

        guardianDids = [];
        requiredGuardianSignatures = 0;
        if (signedEnrollmentJwt.Length is 0 or > MaximumJwtLength ||
            !ValidAudience(verifierAudience) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid,
                out byte[] issuerPublicKey) ||
            independentlyPinnedSha256.Length != 64 ||
            independentlyPinnedSha256.Any(static c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')) ||
            !string.Equals(Fingerprint(signedEnrollmentJwt),
                independentlyPinnedSha256, StringComparison.Ordinal) ||
            !StrictJwtReader.TryRead(signedEnrollmentJwt, HeaderType,
                MaximumJwtLength, out JsonElement policy, KeyId(trustedPreviousIssuerDid)) ||
            !Ed25519JwtSigner.VerifySignedJwt(signedEnrollmentJwt, issuerPublicKey) ||
            policy.EnumerateObject().Count() != 8 ||
            !policy.TryGetProperty("version", out JsonElement version) ||
            version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out int schemaVersion) || schemaVersion != 1 ||
            !StrictJwtReader.TryGetString(policy, "purpose", out string purpose) ||
            !string.Equals(purpose, Purpose, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(policy, "previousIssuer", out string previousIssuer) ||
            !string.Equals(previousIssuer, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(policy, "aud", out string audience) ||
            !string.Equals(audience, verifierAudience.AbsoluteUri, StringComparison.Ordinal) ||
            !policy.TryGetProperty("requiredSignatures", out JsonElement required) ||
            required.ValueKind != JsonValueKind.Number ||
            !required.TryGetInt32(out int threshold) ||
            !policy.TryGetProperty("guardianDids", out JsonElement pins) ||
            pins.ValueKind != JsonValueKind.Array ||
            pins.GetArrayLength() is < 2 or > 5 ||
            !PresentationChallengePolicy.TryGetNumericDate(policy, "iat", out decimal issued) ||
            !PresentationChallengePolicy.TryGetNumericDate(policy, "exp", out decimal expires))
        {
            return false;
        }

        decimal current = PresentationChallengePolicy.NumericDate(now);
        if (issued > current || expires <= current || expires <= issued ||
            expires - issued > MaximumLifetimeSeconds)
        {
            return false;
        }

        var readDids = new List<string>(pins.GetArrayLength());
        foreach (JsonElement pin in pins.EnumerateArray())
        {
            if (pin.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(pin.GetString()))
            {
                return false;
            }

            readDids.Add(pin.GetString()!);
        }

        if (!TryValidatePins(trustedPreviousIssuerDid, readDids, threshold,
                out string[] ordered) ||
            !ordered.SequenceEqual(readDids, StringComparer.Ordinal))
        {
            return false;
        }

        guardianDids = ordered;
        requiredGuardianSignatures = threshold;
        return true;
    }

    /// <summary>
    /// Issue a one-time tenant-bound recovery challenge only for the previously
    /// approved exact original-issuer guardian enrollment. This allocates no
    /// challenge if signature, digest, issuer, audience or validity fails.
    /// </summary>
    public static PresentationChallenge IssueChallenge(IPresentationChallengeStore store,
        Guid verifierTenantId, string signedEnrollmentJwt, string independentlyPinnedSha256,
        string trustedPreviousIssuerDid, Uri verifierAudience, TimeProvider clock,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(clock);

        if (verifierTenantId == Guid.Empty ||
            !TryVerify(signedEnrollmentJwt, trustedPreviousIssuerDid,
                independentlyPinnedSha256, verifierAudience, clock.GetUtcNow(),
                out string[] guardians, out int threshold))
        {
            throw new ArgumentException("A currently valid, independently pinned guardian enrollment is required.");
        }

        return IssuerGuardianRecoveryChallenges.IssueBoundToGuardians(
            store, verifierTenantId, trustedPreviousIssuerDid, guardians,
            threshold, verifierAudience, lifetime);
    }

    /// <summary>
    /// Recheck the independently pinned old-issuer enrollment before consuming
    /// the purpose-separated challenge and the real successor/guardian quorum.
    /// Returns a candidate DID only after successful atomic consumption; the
    /// caller must separately decide organization authority and issuer trust.
    /// </summary>
    public static bool TryVerifyAndConsume(IPresentationChallengeStore store,
        Guid verifierTenantId, string evidenceJson, string signedEnrollmentJwt,
        string independentlyPinnedSha256, string trustedPreviousIssuerDid,
        Uri verifierAudience, string expectedNonce, TimeProvider clock,
        out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(clock);

        successorIssuerDid = string.Empty;
        if (verifierTenantId == Guid.Empty ||
            !TryVerify(signedEnrollmentJwt, trustedPreviousIssuerDid,
                independentlyPinnedSha256, verifierAudience, clock.GetUtcNow(),
                out string[] guardians, out int threshold))
        {
            return false;
        }

        return IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
            store, verifierTenantId, evidenceJson, trustedPreviousIssuerDid,
            guardians, threshold, verifierAudience, expectedNonce, clock,
            out successorIssuerDid);
    }

    private static bool TryValidatePins(string previousIssuerDid,
        IReadOnlyCollection<string> guardians, int threshold, out string[] ordered)
    {
        ordered = [];
        if (guardians.Count is < 2 or > 5 ||
            threshold < 2 || threshold > guardians.Count)
        {
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string did in guardians)
        {
            if (string.IsNullOrWhiteSpace(did) ||
                string.Equals(did, previousIssuerDid, StringComparison.Ordinal) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(did, out _) ||
                !unique.Add(did))
            {
                return false;
            }
        }

        ordered = [.. unique.OrderBy(static did => did, StringComparer.Ordinal)];
        return true;
    }

    private static string KeyId(string did) => did + "#" + did["did:key:".Length..];

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2_048;
}
