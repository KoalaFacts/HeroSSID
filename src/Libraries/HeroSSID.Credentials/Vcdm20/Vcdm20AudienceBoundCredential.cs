using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Opt-in, single-recipient VC2 signed credential identifier profile.
/// The original issuer signs both the exact credential ID and relying-party audience.
/// The verifier must pin issuer, holder, context, type, ID and its own audience.
/// </summary>
public static partial class Vcdm20JoseCredential
{
    /// <summary>
    /// Create a VC2 JWT limited to one HTTPS relying-party audience.
    /// No holder-control proof, recipient identity or business authorization is implied.
    /// </summary>
    public static string CreateForAudienceWithId(
        string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom,
        DateTimeOffset validUntil, Uri credentialId, Uri relyingPartyAudience)
        => throw new NotSupportedException("RED-first: signed VC2 audience issuance is not implemented.");

    /// <summary>
    /// Verify only a genuine VC2 issuer-signed JWT with an exact HTTPS recipient and credential ID.
    /// No claims are released on any failure.
    /// </summary>
    public static bool TryVerifyForAudienceWithId(
        string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        Uri expectedCredentialId, Uri expectedAudience,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        throw new NotSupportedException("RED-first: signed VC2 audience verification is not implemented.");
    }
}
