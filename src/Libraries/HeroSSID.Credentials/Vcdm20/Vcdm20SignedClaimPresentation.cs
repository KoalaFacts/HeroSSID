using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in full-disclosure holder proof plus an independently pinned exact
/// issuer-signed membership claim policy. Does not grant business authority.
/// </summary>
public static class Vcdm20SignedClaimPresentation
{
    /// <summary>
    /// Verify the original genuine issuer-signed VC2 JWT, independently
    /// pinned membership claims, and a genuine one-use holder presentation.
    /// This version deliberately does not check issuer revocation status.
    /// </summary>
    public static Vcdm20PresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredSubjectClaims,
        TimeProvider clock, out string verifiedIssuerDid,
        out JsonElement verifiedSubject)
    {
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;
        if (!TryAuthenticateOriginal(presentationJwt, verifierTenantId,
                expectedAudience, expectedNonce, expectedCredentialType,
                expectedContextUri, challenges, trustedIssuerDids,
                expectedHolderDid, expectedCredentialId,
                requiredSubjectClaims, clock, out _, out string issuer,
                out JsonElement subject))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        // CheckCore bounded VP.exp by the retained challenge and original
        // VC.validUntil before atomically spending the nonce. Their deadlines
        // are therefore no earlier than authenticated VP.exp. Sample time
        // again after issuer/policy checks, not just before them.
        if (!IsAuthenticatedPresentationStillLive(
                presentationJwt, expectedHolderDid, clock.GetUtcNow()))
        {
            return Vcdm20PresentationCheckResult.Invalid;
        }

        verifiedIssuerDid = issuer;
        verifiedSubject = subject;
        return Vcdm20PresentationCheckResult.SignedButStatusUnchecked;
    }

    /// <summary>
    /// Opt-in genuine same-issuer 60-second signed status for the exact
    /// original signed-ID VC2 JWT in a genuine one-use holder presentation.
    /// Require the verifier's independent minimum issuer observation instant
    /// and exact trusted issuer/holder/credential-id/claim policy. Rejections
    /// release no issuer or subject; an authentic but refused proof remains
    /// spent. SignedNotListed is not live revocation or authorization.
    /// </summary>
    public static Vcdm20RevocationCheckResult CheckWithIssuerStatus(
        string presentationJwt, string snapshotJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce, string expectedCredentialType,
        Uri expectedContextUri, IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> trustedIssuerDids, string expectedHolderDid,
        Uri expectedCredentialId, IReadOnlyDictionary<string, string> requiredSubjectClaims,
        DateTimeOffset minimumObservedAtUtc, TimeProvider clock,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(snapshotJwt);
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // The challenge is atomically consumed by the genuine holder/issuer
        // checker before any separately supplied status can be accepted.
        if (!TryAuthenticateOriginal(presentationJwt, verifierTenantId,
                expectedAudience, expectedNonce, expectedCredentialType,
                expectedContextUri, challenges, trustedIssuerDids,
                expectedHolderDid, expectedCredentialId,
                requiredSubjectClaims, clock, out string originalJwt,
                out string issuer, out JsonElement subject))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        // Authenticate the snapshot with the ORIGINAL credential signer.
        // Never trust a presenter-provided issuer claim or a foreign snapshot.
        Vcdm20RevocationCheckResult status =
            Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                snapshotJwt, originalJwt, issuer, clock.GetUtcNow(),
                minimumObservedAtUtc);
        if (status != Vcdm20RevocationCheckResult.SignedNotListed)
        {
            return status;
        }

        // Check the signed VP and status expiry against ONE final clock
        // sample after the expensive genuine holder, issuer and status
        // verification. Both compact JWTs have already been authenticated;
        // re-read only their immutable signed expiry fields, with no new
        // trust decision from unverified or caller-substituted claims.
        DateTimeOffset finalNow = clock.GetUtcNow();
        if (!IsAuthenticatedPresentationStillLive(
                presentationJwt, expectedHolderDid, finalNow) ||
            !IsAuthenticatedStatusStillLive(snapshotJwt, finalNow))
        {
            return Vcdm20RevocationCheckResult.Invalid;
        }

        verifiedIssuerDid = issuer;
        verifiedSubject = subject;
        return Vcdm20RevocationCheckResult.SignedNotListed;
    }

    // These helpers MUST only be used after TryAuthenticateOriginal and,
    // for status, CheckWithObservationCutoff have verified real Ed25519
    // signatures over these exact immutable strings. Parsing never confers
    // provenance on its own.
    private static bool IsAuthenticatedPresentationStillLive(
        string presentationJwt, string expectedHolderDid, DateTimeOffset now)
    {
        if (!expectedHolderDid.StartsWith("did:key:", StringComparison.Ordinal))
        {
            return false;
        }

        string keyId = expectedHolderDid + "#" + expectedHolderDid["did:key:".Length..];
        return StrictJwtReader.TryRead(
                presentationJwt, "vp+jwt", 131_072,
                out JsonElement payload, keyId, "vp") &&
            PresentationChallengePolicy.TryGetNumericDate(
                payload, "exp", out decimal expiry) &&
            expiry > PresentationChallengePolicy.NumericDate(now);
    }

    private static bool IsAuthenticatedStatusStillLive(
        string signedSnapshotJwt, DateTimeOffset now) =>
        StrictJwtReader.TryRead(
            signedSnapshotJwt, "herossid-vc2-revocation-snapshot+jwt",
            65_536, out JsonElement payload) &&
        StrictJwtReader.TryGetTimestamp(payload, "exp", out long expiry) &&
        expiry > now.ToUnixTimeSeconds();

    private static bool TryAuthenticateOriginal(
        string presentationJwt, Guid verifierTenantId,
        string expectedAudience, string expectedNonce,
        string expectedCredentialType, Uri expectedContextUri,
        IPresentationChallengeStore challenges,
        IReadOnlyCollection<string> trustedIssuerDids,
        string expectedHolderDid, Uri expectedCredentialId,
        IReadOnlyDictionary<string, string> requiredSubjectClaims,
        TimeProvider clock, out string originalCredentialJwt,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(trustedIssuerDids);
        ArgumentNullException.ThrowIfNull(expectedHolderDid);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(requiredSubjectClaims);
        ArgumentNullException.ThrowIfNull(clock);

        originalCredentialJwt = string.Empty;
        verifiedIssuerDid = string.Empty;
        verifiedSubject = default;

        // Independently authenticate genuine issuer and holder Ed25519
        // signatures, the verifier-owned tenant/nonce/audience, exact signed
        // credential ID and original lifetime before consuming the nonce.
        if (Vcdm20JosePresentation.CheckWithAuthenticatedOriginalSignedId(
                presentationJwt, verifierTenantId, expectedAudience,
                expectedNonce, expectedCredentialType, expectedContextUri,
                expectedCredentialId, challenges, clock, out _,
                out string authenticOriginalJwt, out string actualHolderDid) !=
            Vcdm20PresentationCheckResult.SignedButStatusUnchecked ||
            !string.Equals(actualHolderDid, expectedHolderDid,
                StringComparison.Ordinal))
        {
            return false;
        }

        // Policy must come from the verifier, not the holder or issuer JWT.
        // Recheck the genuine original against all enrolled issuer/holder
        // pins and exact top-level signed string-claim policy.
        if (!Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
                authenticOriginalJwt, trustedIssuerDids, expectedHolderDid,
                expectedCredentialType, expectedContextUri,
                expectedCredentialId, requiredSubjectClaims, clock.GetUtcNow(),
                out string issuer, out JsonElement subject))
        {
            return false;
        }

        originalCredentialJwt = authenticOriginalJwt;
        verifiedIssuerDid = issuer;
        verifiedSubject = subject;
        return true;
    }
}
