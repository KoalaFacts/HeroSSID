using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>Verifier-owned, exact-original-JWT emergency denial of a holder-bound did:web VC1.1 proof.</summary>
public enum JwtVcJsonPinnedDidWebDenylistResult
{
    /// <summary>Invalid proof, issuer pin, verifier challenge or local denial policy.</summary>
    Invalid,

    /// <summary>Authentic holder and issuer signatures, but the verifier has blocked this exact credential JWT.</summary>
    DeniedByVerifier,

    /// <summary>Authentic issuer and holder signatures plus one-use proof; issuer revocation status remains unchecked.</summary>
    SignedButStatusUnchecked
}

/// <summary>
/// Optional independently maintained verifier emergency blocklist, not issuer
/// revocation, an identity check, business authorization or consent evidence.
/// </summary>
public static class JwtVcJsonPinnedDidWebPresentationDenylist
{
    private const int MaximumDeniedCredentialDigests = 256;

    /// <summary>
    /// Verify both real signatures, independently pinned did:web issuer metadata,
    /// a one-use challenge, and the entire exact original-credential SHA-256 policy
    /// before releasing claims. A valid denied proof consumes its nonce too.
    /// An invalid verifier policy is rejected before any challenge consumption.
    /// </summary>
    public static JwtVcJsonPinnedDidWebDenylistResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IReadOnlyCollection<string> deniedCredentialSha256,
        IPresentationChallengeStore challenges, TimeProvider clock,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(presentationJwt);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(deniedCredentialSha256);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        // The caller's independent local denylist is security policy. Snapshot
        // and validate the WHOLE list before spending an otherwise valid proof.
        // Mixed case, duplicate, malformed, partial, and oversized policies fail.
        if (deniedCredentialSha256.Count > MaximumDeniedCredentialDigests)
        {
            return JwtVcJsonPinnedDidWebDenylistResult.Invalid;
        }

        string[] denied = deniedCredentialSha256.ToArray();
        if (denied.Length != deniedCredentialSha256.Count)
        {
            return JwtVcJsonPinnedDidWebDenylistResult.Invalid;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (string digest in denied)
        {
            if (!IsCanonicalDigest(digest) || !unique.Add(digest))
            {
                return JwtVcJsonPinnedDidWebDenylistResult.Invalid;
            }
        }

        // Do not implement a second weaker signature parser here. This exact
        // existing did:web verifier checks the independently pinned issuer
        // method/key/name/ID, the genuine holder did:key signature, the original
        // embedded issuer JWT, and atomically consumes the verifier challenge.
        if (JwtVcJsonPinnedDidWebIssuerPresentation.Check(
                presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
                trustedIssuerDid, trustedVerificationMethodId,
                independentlyPinnedIssuerPublicKey, expectedIssuerName,
                expectedCredentialId, expectedCredentialType, expectedSubjectContextUri,
                challenges, clock, out JsonElement signedSubject) !=
            JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked ||
            !TryGetExactOriginalCredential(presentationJwt, out string originalJwt))
        {
            return JwtVcJsonPinnedDidWebDenylistResult.Invalid;
        }

        // Hash the exact issuer-signed compact credential INSIDE the authenticated
        // holder proof. Hashing the VP or trusting an external credential selector
        // would permit an attacker to bypass a verifier's emergency block.
        string digestOfOriginal = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(originalJwt)));
        if (unique.Contains(digestOfOriginal))
        {
            return JwtVcJsonPinnedDidWebDenylistResult.DeniedByVerifier;
        }

        verifiedSubject = signedSubject;
        return JwtVcJsonPinnedDidWebDenylistResult.SignedButStatusUnchecked;
    }

    private static bool TryGetExactOriginalCredential(
        string presentationJwt, out string originalCredentialJwt)
    {
        originalCredentialJwt = string.Empty;
        if (!StrictJwtReader.TryRead(presentationJwt, "vp+jwt", 131_072,
                out JsonElement holderClaims) ||
            !holderClaims.TryGetProperty("vp", out JsonElement vp) ||
            vp.ValueKind != JsonValueKind.Object ||
            !vp.TryGetProperty("verifiableCredential", out JsonElement credentials) ||
            credentials.ValueKind != JsonValueKind.Array ||
            credentials.GetArrayLength() != 1 ||
            credentials[0].ValueKind != JsonValueKind.String)
        {
            return false;
        }

        string? jwt = credentials[0].GetString();
        if (string.IsNullOrEmpty(jwt) ||
            !StrictJwtReader.IsCanonicalCompact(jwt, 65_536))
        {
            return false;
        }

        originalCredentialJwt = jwt;
        return true;
    }

    private static bool IsCanonicalDigest(string? digest) =>
        digest is { Length: 64 } &&
        digest.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
