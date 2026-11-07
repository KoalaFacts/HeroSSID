using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in original issuer-signed direct VC2 JWT admission for an independently
/// enrolled did:web assertion key AND one exact HTTPS relying-party audience.
/// This is issuer authenticity and signed recipient policy, not holder proof.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Verify the exact issuer DID, assertion method, raw Ed25519 public key,
    /// descriptive issuer name, credential ID, holder, type, context, validity
    /// and signed recipient aud before releasing the original subject.
    /// All pins are supplied independently of the untrusted JWT.
    /// </summary>
    public static bool TryVerifyPinnedDidWebIssuerForAudienceWithId(
        string jwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, Uri expectedAudience,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;

        if (!ValidIssuerName(expectedIssuerName) ||
            !ValidCredentialId(expectedCredentialId) ||
            !ValidAudience(expectedAudience))
        {
            return false;
        }

        return TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid,
            expectedCredentialType, expectedSubjectContextUri, now,
            out verifiedSubject, out _, requiresCredentialId: true,
            expectedIssuerName: expectedIssuerName,
            expectedCredentialId: expectedCredentialId,
            expectedAudience: expectedAudience,
            pinnedDidWebMethod: trustedVerificationMethodId,
            pinnedDidWebKey: independentlyPinnedIssuerPublicKey);
    }
}
