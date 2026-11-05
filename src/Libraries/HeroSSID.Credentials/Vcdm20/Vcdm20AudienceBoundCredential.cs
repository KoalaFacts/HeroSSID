using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in, single-recipient VC2 signed credential identifier profile.
/// The original issuer signs both the exact credential ID and relying-party audience.
/// The verifier must independently pin issuer, holder, context, type, ID and its own audience.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Create a direct VC2 JWT limited to one canonical HTTPS relying-party audience.
    /// This is not a holder possession proof or business authorization.
    /// </summary>
    public static string CreateForAudienceWithId(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom,
        DateTimeOffset validUntil, Uri credentialId, Uri relyingPartyAudience)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(relyingPartyAudience);
        return CreateCore(issuerDid, holderDid, credentialType,
            subjectContextUri, credentialSubject, issuerPrivateKey,
            validFrom, validUntil, credentialId, audience: relyingPartyAudience);
    }

    /// <summary>
    /// Accept only a real issuer-signed VC2 JWT for this independently pinned HTTPS
    /// recipient and exact original signed credential ID. Failed validation never
    /// releases subject claims. Consent, holder control and status are separate.
    /// </summary>
    public static bool TryVerifyForAudienceWithId(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        Uri expectedCredentialId, Uri expectedAudience,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        return ValidCredentialId(expectedCredentialId) &&
            ValidAudience(expectedAudience) &&
            TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid,
                expectedCredentialType, expectedSubjectContextUri,
                now, out verifiedSubject, out _, requiresCredentialId: true,
                expectedCredentialId: expectedCredentialId,
                expectedAudience: expectedAudience);
    }
}
