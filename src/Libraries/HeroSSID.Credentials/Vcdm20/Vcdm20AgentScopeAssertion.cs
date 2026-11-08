using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// An issuer-signed, verifier-recipient-bound agent action assertion.
/// It is not holder key control or a business authorization decision.
/// </summary>
public static class Vcdm20AgentScopeAssertion
{
    public const string CredentialType = "AgentScopeCredential";

    public static string Create(
        string issuerDid, string agentDid, Uri subjectContextUri,
        Uri credentialId, Uri recipient, Uri resource, string action,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil)
        => throw new NotSupportedException("Agent scope issuance is not implemented.");

    public static bool TryVerify(
        string originalJwt, string trustedIssuerDid, string expectedAgentDid,
        Uri expectedContextUri, Uri expectedCredentialId, Uri expectedRecipient,
        Uri expectedResource, string expectedAction, DateTimeOffset now,
        out JsonElement verifiedScope)
    {
        verifiedScope = default;
        throw new NotSupportedException("Agent scope verification is not implemented.");
    }
}
