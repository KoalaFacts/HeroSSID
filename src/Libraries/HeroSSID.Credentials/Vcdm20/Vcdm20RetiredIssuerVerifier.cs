using System.Text.Json;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>An independently registered SHA-256 of one exact original VC2 JWT from a retired issuer.</summary>
public sealed record Vcdm20RetiredCredentialPin(string IssuerDid, string CredentialSha256);

/// <summary>
/// Verifier-controlled trust transition: active issuers may issue new VC2s;
/// retired issuer credentials require a separately registered exact JWT pin.
/// </summary>
public static class Vcdm20RetiredIssuerVerifier
{
    public static Vcdm20VerifierPolicyResult Check(
        string credentialJwt, IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        throw new NotSupportedException("VC2 retired exact-credential trust not implemented.");
    }

    public static Vcdm20VerifierPolicyResult CheckWithStatus(
        string credentialJwt, string revocationSnapshotJwt,
        IReadOnlyCollection<string> activeIssuerDids,
        IReadOnlyCollection<Vcdm20RetiredCredentialPin> retiredCredentialPins,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject)
    {
        throw new NotSupportedException("VC2 retired exact-credential status not implemented.");
    }
}
