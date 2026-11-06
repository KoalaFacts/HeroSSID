using System.Text.Json;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Explicit SDK-only full-disclosure holder VP for a genuine VC1.1 JWT signed
/// by an independently pinned did:web issuer assertion key. No network
/// verifier authentication, third-party Wallet interoperability or consent UI.
/// </summary>
public static class JwtVcJsonPinnedDidWebIssuerPresentation
{
    /// <summary>
    /// A caller MUST independently authenticate the verifier's challenge,
    /// issuer DID, Ed25519 assertion method/key and exact signed metadata,
    /// show every disclosed claim, and obtain informed consent before signing.
    /// The passed challenge is app-authenticated, not a standard OpenID4VP request.
    /// </summary>
    public static string Create(
        PresentationChallenge authenticatedChallenge, string credentialJwt,
        string trustedIssuerDid, string trustedVerificationMethodId,
        byte[] independentlyPinnedIssuerPublicKey, string expectedIssuerName,
        Uri expectedCredentialId, string expectedCredentialType,
        Uri expectedSubjectContextUri, string holderDid, byte[] holderSeed,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(authenticatedChallenge);
        ArgumentNullException.ThrowIfNull(credentialJwt);
        ArgumentNullException.ThrowIfNull(trustedIssuerDid);
        ArgumentNullException.ThrowIfNull(trustedVerificationMethodId);
        ArgumentNullException.ThrowIfNull(independentlyPinnedIssuerPublicKey);
        ArgumentNullException.ThrowIfNull(expectedIssuerName);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialType);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(holderSeed);
        ArgumentNullException.ThrowIfNull(clock);

        var now = clock.GetUtcNow();
        if (!string.Equals(authenticatedChallenge.TrustedIssuerDid,
                trustedIssuerDid, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.IsValidNonce(authenticatedChallenge.Nonce) ||
            string.IsNullOrWhiteSpace(authenticatedChallenge.Audience) ||
            authenticatedChallenge.Audience.Length > PresentationChallengePolicy.MaximumIdentifierLength ||
            authenticatedChallenge.ExpiresAt <= now ||
            authenticatedChallenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime) ||
            (authenticatedChallenge.CredentialType is null) !=
                (authenticatedChallenge.SubjectContextUri is null) ||
            (authenticatedChallenge.CredentialType is not null &&
                !string.Equals(authenticatedChallenge.CredentialType,
                    expectedCredentialType, StringComparison.Ordinal)) ||
            (authenticatedChallenge.SubjectContextUri is not null &&
                !string.Equals(authenticatedChallenge.SubjectContextUri.AbsoluteUri,
                    expectedSubjectContextUri.AbsoluteUri, StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                "An independently authenticated live verifier challenge and exact issuer policy are required.",
                nameof(authenticatedChallenge));
        }

        var pin = new PinnedDidWebIssuerPresentationPolicy(
            trustedIssuerDid, trustedVerificationMethodId,
            independentlyPinnedIssuerPublicKey.ToArray(),
            expectedIssuerName, expectedCredentialId);

        // Reuse the proven holder VP construction, but require a real did:web
        // issuer signature under the independent pin, not a did:key fallback.
        return JwtVcJsonPresentation.CreateForAuthenticatedChallenge(
            authenticatedChallenge, credentialJwt, expectedCredentialType,
            expectedSubjectContextUri, holderDid, holderSeed, clock,
            pinnedDidWebIssuer: pin);
    }

    /// <summary>
    /// Verify the original did:web issuer JWT and holder-signed VP against
    /// a verifier-owned challenge, then atomically consume the nonce before
    /// exposing claims. The caller independently owns issuer trust and
    /// authorization policy. Successful signatures do not prove consent,
    /// live non-revocation, real identity or Agent/business authority.
    /// </summary>
    public static JwtVcJsonPresentationCheckResult Check(
        string presentationJwt, Guid verifierTenantId, string expectedAudience,
        string expectedNonce, string trustedIssuerDid,
        string trustedVerificationMethodId, byte[] independentlyPinnedIssuerPublicKey,
        string expectedIssuerName, Uri expectedCredentialId,
        string expectedCredentialType, Uri expectedSubjectContextUri,
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
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        verifiedSubject = default;

        var pin = new PinnedDidWebIssuerPresentationPolicy(
            trustedIssuerDid, trustedVerificationMethodId,
            independentlyPinnedIssuerPublicKey.ToArray(),
            expectedIssuerName, expectedCredentialId);
        return JwtVcJsonPresentation.CheckWithPinnedDidWebIssuer(
            presentationJwt, verifierTenantId, expectedAudience, expectedNonce,
            expectedCredentialType, expectedSubjectContextUri, challenges,
            clock, pin, out verifiedSubject);
    }
}
