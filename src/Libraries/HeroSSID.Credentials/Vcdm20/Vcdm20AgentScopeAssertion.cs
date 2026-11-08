using System.Globalization;
using System.Text.Json;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// A restricted application-specific VC2 issuer assertion that an agent DID
/// has one named scope for one HTTPS resource and relying-party recipient.
/// This verifies issuer provenance, NOT private-key possession, consent,
/// current status, real organisation identity or business authorization.
/// </summary>
public static class Vcdm20AgentScopeAssertion
{
    public const string CredentialType = "AgentScopeCredential";

    private static readonly TimeSpan MaximumValidity = TimeSpan.FromMinutes(15);
    private static readonly string[] DateFormats =
    [
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"
    ];

    /// <summary>
    /// The issuer signs the complete direct VC2 JWT using its own Ed25519
    /// seed. The holder is the named agent DID, not the issuer or verifier.
    /// A custom versioned context must define the application-specific
    /// action and resource terms. The caller retains and clears the seed.
    /// </summary>
    public static string Create(
        string issuerDid, string agentDid, Uri subjectContextUri,
        Uri credentialId, Uri recipient, Uri resource, string action,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(agentDid);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        if (!ValidResource(resource) || !ValidAction(action) ||
            validUntil <= validFrom || validUntil - validFrom > MaximumValidity)
        {
            throw new ArgumentException(
                "Invalid agent action, resource or scope assertion validity.");
        }

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            id = agentDid,
            action,
            resource = resource.AbsoluteUri
        }));
        // Reuse the exact VCDM2 direct vc+jwt issuer-signed credential and
        // independent issuer-key self-check, never a holder-re-signed claim.
        return Vcdm20JoseCredential.CreateForAudienceWithId(
            issuerDid, agentDid, CredentialType, subjectContextUri,
            subject.RootElement, issuerPrivateKey, validFrom, validUntil,
            credentialId, recipient);
    }

    /// <summary>
    /// Require independent verifier pins for issuer, agent, type, context,
    /// signed credential ID, HTTPS recipient, resource and single action.
    /// Only return an authenticated scope on complete success; callers must
    /// separately verify agent private-key control, current status and their
    /// own purpose-specific authority policy before taking any action.
    /// </summary>
    public static bool TryVerify(
        string originalJwt, string trustedIssuerDid, string expectedAgentDid,
        Uri expectedContextUri, Uri expectedCredentialId, Uri expectedRecipient,
        Uri expectedResource, string expectedAction, DateTimeOffset now,
        out JsonElement verifiedScope)
    {
        ArgumentNullException.ThrowIfNull(originalJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedAgentDid);
        ArgumentNullException.ThrowIfNull(expectedContextUri);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedRecipient);
        ArgumentNullException.ThrowIfNull(expectedResource);

        verifiedScope = default;
        if (!ValidResource(expectedResource) || !ValidAction(expectedAction) ||
            !Vcdm20JoseCredential.TryVerifyForAudienceWithId(
                originalJwt, trustedIssuerDid, expectedAgentDid,
                CredentialType, expectedContextUri, expectedCredentialId,
                expectedRecipient, now, out JsonElement subject) ||
            subject.EnumerateObject().Count() != 3 ||
            !TryGetExactString(subject, "id", expectedAgentDid) ||
            !TryGetExactString(subject, "action", expectedAction) ||
            !TryGetExactString(subject, "resource", expectedResource.AbsoluteUri) ||
            !HasShortSignedLifetime(originalJwt))
        {
            return false;
        }

        verifiedScope = subject;
        return true;
    }

    private static bool TryGetExactString(JsonElement value, string name, string expected) =>
        value.TryGetProperty(name, out JsonElement property) &&
        property.ValueKind == JsonValueKind.String &&
        string.Equals(property.GetString(), expected, StringComparison.Ordinal);

    private static bool ValidResource(Uri resource) =>
        resource.IsAbsoluteUri &&
        string.Equals(resource.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(resource.Host) &&
        string.IsNullOrEmpty(resource.UserInfo) &&
        string.IsNullOrEmpty(resource.Fragment) &&
        string.IsNullOrEmpty(resource.Query) &&
        resource.AbsoluteUri.Length <= 2048 &&
        string.Equals(resource.OriginalString, resource.AbsoluteUri, StringComparison.Ordinal);

    // One literal ASCII action, never a wildcard, role list or arbitrary
    // expression. Applications must define and approve the vocabulary.
    private static bool ValidAction(string? action)
    {
        if (string.IsNullOrEmpty(action) || action.Length > 64 ||
            action[0] is < 'a' or > 'z')
        {
            return false;
        }

        bool separator = false;
        foreach (char character in action)
        {
            if (character is >= 'a' and <= 'z' or >= '0' and <= '9')
            {
                separator = false;
            }
            else if (character is '.' or ':' or '-' && !separator)
            {
                separator = true;
            }
            else
            {
                return false;
            }
        }

        return !separator;
    }

    private static bool HasShortSignedLifetime(string originalJwt)
    {
        // Called only AFTER the original Ed25519 signature, issuer and
        // recipient policy have passed. Never trust a decoded JWT directly.
        try
        {
            using var document = JsonDocument.Parse(
                Ed25519JwtSigner.ExtractPayload(originalJwt));
            JsonElement root = document.RootElement;
            if (!root.TryGetProperty("validFrom", out JsonElement fromValue) ||
                !root.TryGetProperty("validUntil", out JsonElement untilValue) ||
                fromValue.ValueKind != JsonValueKind.String ||
                untilValue.ValueKind != JsonValueKind.String ||
                !DateTimeOffset.TryParseExact(
                    fromValue.GetString(), DateFormats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset validFrom) ||
                !DateTimeOffset.TryParseExact(
                    untilValue.GetString(), DateFormats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset validUntil))
            {
                return false;
            }

            return validUntil > validFrom && validUntil - validFrom <= MaximumValidity;
        }
        catch (Exception exception) when (
            exception is JsonException or ArgumentException or FormatException)
        {
            return false;
        }
    }
}
