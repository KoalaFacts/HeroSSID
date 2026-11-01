using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Verifier-pinned quorum evidence for recovery after loss of an issuer's Ed25519 key.
/// Guardians and the proposed successor sign one exact, nonce- and audience-bound
/// statement. The original issuer's private key is deliberately not required.
/// This private HeroSSID evidence format is NOT automatic issuer trust promotion,
/// DID control transfer, organization identity, holder possession, or authority.
/// The relying party must have pre-enrolled guardians independently and must
/// atomically consume its one-use nonce before any separate trust-policy change.
/// </summary>
public static class IssuerGuardianRecovery
{
    private const string HeaderType = "herossid-issuer-guardian-recovery+jwt";
    private const string Purpose = "issuer-key-guardian-recovery";
    private const int MaximumJwtLength = 4_096;
    private const int MaximumEvidenceLength = 32_768;
    private const int MaximumGuardians = 5;
    private const decimal LifetimeSeconds = 300m;

    /// <summary>
    /// Sign a five-minute recovery statement with the candidate successor's
    /// Ed25519 seed and at least two distinct independent guardian seeds.
    /// An issuer organization must provision the trusted guardian DIDs through
    /// a separate trusted channel BEFORE old-key loss. This method does not
    /// register guardians, assign any DID, persist data or promote a new key.
    /// The caller owns and clears all private-key buffers.
    /// </summary>
    public static string Create(string previousIssuerDid, string successorIssuerDid,
        byte[] successorSeed, IReadOnlyDictionary<string, byte[]> guardianSeeds,
        Uri verifierAudience, string nonce, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(previousIssuerDid);
        ArgumentNullException.ThrowIfNull(successorIssuerDid);
        ArgumentNullException.ThrowIfNull(successorSeed);
        ArgumentNullException.ThrowIfNull(guardianSeeds);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(previousIssuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(successorIssuerDid, out _) ||
            string.Equals(previousIssuerDid, successorIssuerDid, StringComparison.Ordinal) ||
            successorSeed.Length != 32 || successorSeed.All(static b => b == 0) ||
            guardianSeeds.Count is < 2 or > MaximumGuardians ||
            !ValidAudience(verifierAudience) || !ValidNonce(nonce))
        {
            throw new ArgumentException("Distinct issuer successor, two guardian seeds, HTTPS verifier and strong nonce required.");
        }

        foreach (var guardian in guardianSeeds)
        {
            if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(guardian.Key, out _) ||
                string.Equals(guardian.Key, previousIssuerDid, StringComparison.Ordinal) ||
                string.Equals(guardian.Key, successorIssuerDid, StringComparison.Ordinal) ||
                guardian.Value is not { Length: 32 } ||
                guardian.Value.All(static b => b == 0))
            {
                throw new ArgumentException("Guardian keys must be distinct from the old and new issuer and contain valid Ed25519 seeds.", nameof(guardianSeeds));
            }
        }

        decimal issued = PresentationChallengePolicy.NumericDate(clock.GetUtcNow());
        decimal expires = issued + LifetimeSeconds;
        if (issued < 0m || expires >= 253402300800m)
        {
            throw new ArgumentException("The recovery evidence clock is outside the supported UTC range.", nameof(clock));
        }

        string statement = JsonSerializer.Serialize(new
        {
            version = 1,
            purpose = Purpose,
            previousIssuer = previousIssuerDid,
            successorIssuer = successorIssuerDid,
            aud = verifierAudience.AbsoluteUri,
            nonce,
            iat = issued,
            exp = expires
        });
        string successorSignature = Ed25519JwtSigner.CreateSignedJwt(
            Header(successorIssuerDid), statement, successorSeed);
        var guardianSignatures = new List<string>(guardianSeeds.Count);
        foreach (var guardian in guardianSeeds.OrderBy(static item => item.Key, StringComparer.Ordinal))
        {
            guardianSignatures.Add(Ed25519JwtSigner.CreateSignedJwt(
                Header(guardian.Key), statement, guardian.Value));
        }

        string evidence = JsonSerializer.Serialize(new { successorSignature, guardianSignatures });
        if (evidence.Length > MaximumEvidenceLength ||
            !TryVerify(evidence, previousIssuerDid, guardianSeeds.Keys.ToArray(),
                guardianSeeds.Count, verifierAudience, nonce, clock.GetUtcNow(), out string verifiedSuccessor) ||
            !string.Equals(verifiedSuccessor, successorIssuerDid, StringComparison.Ordinal))
        {
            throw new ArgumentException("The proposed successor or a guardian seed cannot authenticate its pinned DID.");
        }

        return evidence;
    }

    /// <summary>
    /// Verify a real successor key signature plus a quorum of separately
    /// pre-enrolled guardian DIDs on the identical statement. Pins, audience,
    /// nonce and threshold MUST come from the relying party's own policy,
    /// never the recovery message. This returns evidence only; it never
    /// consumes the nonce or enrolls a new issuer. The caller must enforce
    /// a one-use challenge and independent authorization/compromise policy.
    /// </summary>
    public static bool TryVerify(string proofJson, string trustedPreviousIssuerDid,
        IReadOnlyCollection<string> trustedGuardianDids, int requiredGuardianSignatures,
        Uri expectedVerifierAudience, string expectedNonce, DateTimeOffset now,
        out string successorIssuerDid)
    {
        ArgumentNullException.ThrowIfNull(proofJson);
        ArgumentNullException.ThrowIfNull(trustedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedGuardianDids);
        ArgumentNullException.ThrowIfNull(expectedVerifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);

        successorIssuerDid = string.Empty;
        if (proofJson.Length is 0 or > MaximumEvidenceLength ||
            !ValidAudience(expectedVerifierAudience) || !ValidNonce(expectedNonce) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedPreviousIssuerDid, out _) ||
            trustedGuardianDids.Count is < 2 or > MaximumGuardians ||
            requiredGuardianSignatures < 2 || requiredGuardianSignatures > trustedGuardianDids.Count)
        {
            return false;
        }

        // The trusted set must be unambiguous. Duplicate entries never count
        // as separate approvals; old issuer signatures cannot be guardians.
        var pins = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string guardianDid in trustedGuardianDids)
        {
            if (string.Equals(guardianDid, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(guardianDid, out byte[] publicKey) ||
                !pins.TryAdd(guardianDid, publicKey))
            {
                return false;
            }
        }

        try
        {
            using var evidenceDoc = JsonDocument.Parse(proofJson, new JsonDocumentOptions { MaxDepth = 6 });
            JsonElement root = evidenceDoc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Count() != 2 ||
                !StrictJwtReader.TryGetString(root, "successorSignature", out string successorJwt) ||
                !root.TryGetProperty("guardianSignatures", out JsonElement approvals) ||
                approvals.ValueKind != JsonValueKind.Array ||
                approvals.GetArrayLength() < requiredGuardianSignatures ||
                approvals.GetArrayLength() > pins.Count ||
                !StrictJwtReader.IsCanonicalCompact(successorJwt, MaximumJwtLength))
            {
                return false;
            }

            // Derive the candidate only for key lookup; no unverified claim is
            // ever returned. StrictJwtReader then validates the complete JOSE
            // header, nested JSON uniqueness, correct kid and canonical JWS.
            using var candidateDoc = JsonDocument.Parse(
                Ed25519JwtSigner.ExtractPayload(successorJwt),
                new JsonDocumentOptions { MaxDepth = 6 });
            if (!StrictJwtReader.TryGetString(candidateDoc.RootElement, "successorIssuer", out string candidate) ||
                string.Equals(candidate, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
                pins.ContainsKey(candidate) ||
                candidate.Length > 128 ||
                !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(candidate, out byte[] successorPublicKey) ||
                !StrictJwtReader.TryRead(successorJwt, HeaderType, MaximumJwtLength,
                    out JsonElement signedStatement, KeyId(candidate)) ||
                signedStatement.EnumerateObject().Count() != 8 ||
                !Ed25519JwtSigner.VerifySignedJwt(successorJwt, successorPublicKey) ||
                !signedStatement.TryGetProperty("version", out JsonElement version) ||
                version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out int v) || v != 1 ||
                !StrictJwtReader.TryGetString(signedStatement, "purpose", out string purpose) ||
                !string.Equals(purpose, Purpose, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(signedStatement, "previousIssuer", out string previous) ||
                !string.Equals(previous, trustedPreviousIssuerDid, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(signedStatement, "successorIssuer", out string signedSuccessor) ||
                !string.Equals(signedSuccessor, candidate, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(signedStatement, "aud", out string audience) ||
                !string.Equals(audience, expectedVerifierAudience.AbsoluteUri, StringComparison.Ordinal) ||
                !StrictJwtReader.TryGetString(signedStatement, "nonce", out string nonce) ||
                !string.Equals(nonce, expectedNonce, StringComparison.Ordinal) ||
                !PresentationChallengePolicy.TryGetNumericDate(signedStatement, "iat", out decimal issued) ||
                !PresentationChallengePolicy.TryGetNumericDate(signedStatement, "exp", out decimal expires))
            {
                return false;
            }

            decimal current = PresentationChallengePolicy.NumericDate(now);
            if (issued > current || expires <= current || expires <= issued ||
                expires - issued > LifetimeSeconds || expires - current > LifetimeSeconds)
            {
                return false;
            }

            var seenGuardianDids = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement approval in approvals.EnumerateArray())
            {
                if (approval.ValueKind != JsonValueKind.String)
                {
                    return false;
                }

                string? jwt = approval.GetString();
                if (string.IsNullOrEmpty(jwt) ||
                    !StrictJwtReader.IsCanonicalCompact(jwt, MaximumJwtLength))
                {
                    return false;
                }

                string? matchedDid = null;
                foreach (var pin in pins)
                {
                    if (StrictJwtReader.TryRead(jwt, HeaderType, MaximumJwtLength,
                            out JsonElement guardianStatement, KeyId(pin.Key)) &&
                        string.Equals(guardianStatement.GetRawText(),
                            signedStatement.GetRawText(), StringComparison.Ordinal) &&
                        Ed25519JwtSigner.VerifySignedJwt(jwt, pin.Value))
                    {
                        matchedDid = pin.Key;
                        break;
                    }
                }

                if (matchedDid is null || !seenGuardianDids.Add(matchedDid))
                {
                    return false;
                }
            }

            if (seenGuardianDids.Count < requiredGuardianSignatures)
            {
                return false;
            }

            successorIssuerDid = candidate;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string Header(string did) =>
        JsonSerializer.Serialize(new { alg = "EdDSA", typ = HeaderType, kid = KeyId(did) });

    private static string KeyId(string did) => did + "#" + did["did:key:".Length..];

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2_048;

    private static bool ValidNonce(string nonce) =>
        nonce.Length is >= 20 and <= 128 &&
        nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
