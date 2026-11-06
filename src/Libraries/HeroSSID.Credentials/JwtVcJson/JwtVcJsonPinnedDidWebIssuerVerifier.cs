using System.Text.Json;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Opt-in verification of an original VC1.1 jwt_vc_json signed by a did:web
/// issuer's separately enrolled Ed25519 assertion key. The verifier independently
/// supplies the exact DID, verification method ID, and raw 32-byte public key.
/// No DID resolution, document fetch, key enrollment or trust promotion occurs.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerVerifier
{
    /// <summary>
    /// Verify the original issuer signature and strict JWT VC1.1 issuer/holder,
    /// context, type and validity. Claims are returned only on complete success.
    /// Supports the repository's offline did:web publication profile (lowercase
    /// ASCII DNS domain, optional bounded ASCII path) and key-1/key-2 method IDs.
    /// Before calling, the application must independently establish which
    /// assertion method/public key is authorized for this issuer and purpose.
    /// This does not prove domain ownership, identity, revocation or authority.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedHolderDid, string expectedCredentialType,
        Uri expectedSubjectContextUri, DateTimeOffset now,
        out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;

        if (!IsRestrictedDidWeb(trustedIssuerDid) ||
            !(string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-1",
                StringComparison.Ordinal) ||
              string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-2",
                StringComparison.Ordinal)) ||
            independentlyPinnedIssuerPublicKey.Length != 32 ||
            independentlyPinnedIssuerPublicKey.All(static b => b == 0))
        {
            return false;
        }

        // Use a stable copy of the pre-enrolled key; the caller may reuse or
        // clear its input buffer, but the verification must use one key.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        return JwtVcJsonCredential.TryVerifyPinnedDidWebIssuerCore(
            jwt, trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
            expectedHolderDid, expectedCredentialType, expectedSubjectContextUri,
            now, out verifiedSubject);
    }

    /// <summary>
    /// Require an exact signed descriptive issuer name and credential ID in
    /// addition to the separately enrolled did:web Ed25519 assertion key.
    /// No issuer enrollment, DID resolution, holder proof or business
    /// authorization occurs.
    /// </summary>
    public static bool TryVerifyWithPinnedIssuerNameAndId(
        string jwt, string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;

        if (!IsRestrictedDidWeb(trustedIssuerDid) ||
            !(string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-1",
                StringComparison.Ordinal) ||
              string.Equals(trustedVerificationMethodId, trustedIssuerDid + "#key-2",
                StringComparison.Ordinal)) ||
            independentlyPinnedIssuerPublicKey.Length != 32 ||
            independentlyPinnedIssuerPublicKey.All(static b => b == 0))
        {
            return false;
        }

        // The key is enrolled out of band. Verify the original JWT signature
        // and signed metadata together against one stable snapshot of that pin.
        byte[] pinnedKey = independentlyPinnedIssuerPublicKey.ToArray();
        return JwtVcJsonCredential.TryVerifyPinnedDidWebIssuerMetadataCore(
            jwt, trustedIssuerDid, trustedVerificationMethodId, pinnedKey,
            expectedIssuerName, expectedCredentialId, expectedHolderDid,
            expectedCredentialType, expectedSubjectContextUri, now,
            out verifiedSubject);
    }

    internal static bool IsRestrictedDidWeb(string did)
    {
        const string prefix = "did:web:";
        if (did.Length > 512 || !did.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = did[prefix.Length..].Split(':');
        if (parts.Length is < 1 or > 9 || !IsValidDomain(parts[0]))
        {
            return false;
        }

        foreach (string segment in parts.Skip(1))
        {
            if (segment.Length is < 1 or > 64 ||
                !segment.All(static c => char.IsAsciiLetterOrDigit(c) ||
                    c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsValidDomain(string domain)
    {
        if (domain.Length is < 4 or > 253)
        {
            return false;
        }

        string[] labels = domain.Split('.');
        if (labels.Length < 2 || !labels[^1].Any(static c => c is >= 'a' and <= 'z'))
        {
            return false;
        }

        foreach (string label in labels)
        {
            if (label.Length is < 1 or > 63 ||
                !IsAsciiLowerAlphanumeric(label[0]) ||
                !IsAsciiLowerAlphanumeric(label[^1]) ||
                !label.All(static c => IsAsciiLowerAlphanumeric(c) || c == '-'))
            {
                return false;
            }
        }

        // Match the existing restricted offline did:web publisher: reject
        // Unicode, punycode ambiguities and alternate IPv4/octal host spelling.
        return Uri.TryCreate("https://" + domain + "/", UriKind.Absolute,
            out Uri? publicationHost) &&
            publicationHost.HostNameType == UriHostNameType.Dns &&
            string.Equals(publicationHost.Host, domain, StringComparison.Ordinal);
    }

    private static bool IsAsciiLowerAlphanumeric(char c) =>
        c is >= 'a' and <= 'z' or >= '0' and <= '9';
}
