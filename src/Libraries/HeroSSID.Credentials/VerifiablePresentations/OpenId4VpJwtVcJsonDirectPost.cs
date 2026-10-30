using System.Net;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>The verifier-authenticated details of a bounded JWT VC JSON direct_post request.</summary>
public sealed record JwtVcJsonDirectPostRequest(
    PresentationChallenge Challenge, string ClientId, Uri ResponseUri, string CredentialType);

/// <summary>
/// A bounded signed OpenID4VP 1.0 request and direct_post response for the
/// standard jwt_vc_json Credential Format Identifier (VC Data Model 1.1).
/// HeroSSID-specific, signed issuer and subject vocabulary constraints remain;
/// this is not full protocol conformance or third-party wallet interoperability.
/// </summary>
public static class OpenId4VpJwtVcJsonDirectPost
{
    private const string RequestAudience = "https://self-issued.me/v2";
    private const string CredentialQueryId = "jwt_vc_json_credential";
    private const int MaximumRequestLength = 16_384;
    private const int MaximumResponseLength = 180_000;
    private const int MaximumPresentationLength = 131_072;
    private static readonly string[] EdDsaAlgorithms = ["EdDSA"];

    /// <summary>
    /// Sign an already-issued and retained verifier-owned challenge with the
    /// verifier's real Ed25519 did:key. The challenge issuer is an explicit
    /// verifier policy, not a wallet trust registry.
    /// </summary>
    public static string CreateSignedRequest(PresentationChallenge challenge, string verifierDid,
        byte[] verifierPrivateKey, Uri responseUri, string credentialType,
        Uri subjectContextUri, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(verifierPrivateKey);
        ArgumentNullException.ThrowIfNull(responseUri);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);

        DateTimeOffset now = clock.GetUtcNow();
        string clientId = "decentralized_identifier:" + verifierDid;
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(verifierDid, out var verifierKey) ||
            verifierPrivateKey.Length != 32 || verifierPrivateKey.All(static value => value == 0) ||
            !IsHttpsEndpoint(responseUri) || !IsValidContext(subjectContextUri) ||
            !IsValidCredentialType(credentialType) ||
            !string.Equals(challenge.Audience, clientId, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.IsValidNonce(challenge.Nonce) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(challenge.TrustedIssuerDid, out _) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("A retained challenge, separately trusted issuer, signed DID, HTTPS callback and bounded VC type are required.", nameof(challenge));
        }

        string payload = JsonSerializer.Serialize(new
        {
            client_id = clientId,
            response_type = "vp_token",
            response_mode = "direct_post",
            response_uri = responseUri.OriginalString,
            nonce = challenge.Nonce,
            state = challenge.Nonce,
            dcql_query = new
            {
                credentials = new[]
                {
                    new
                    {
                        id = CredentialQueryId,
                        format = "jwt_vc_json",
                        require_cryptographic_holder_binding = true,
                        meta = new { type_values = new[] { new[] { "VerifiableCredential", credentialType } } }
                    }
                }
            },
            client_metadata = new
            {
                vp_formats_supported = new
                {
                    jwt_vc_json = new { alg_values = EdDsaAlgorithms }
                }
            },
            // Signed application policy extensions, not standard DCQL fields.
            herossid_trusted_issuer_did = challenge.TrustedIssuerDid,
            herossid_subject_context_uri = subjectContextUri.AbsoluteUri,
            aud = RequestAudience,
            iat = PresentationChallengePolicy.NumericDate(now),
            exp = PresentationChallengePolicy.NumericDate(challenge.ExpiresAt)
        });
        string kid = verifierDid + "#" + verifierDid["did:key:".Length..];
        string header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = "oauth-authz-req+jwt", kid });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, verifierPrivateKey);
        if (signed.Length > MaximumRequestLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, verifierKey))
        {
            throw new ArgumentException("The verifier signing key does not control the DID or request is too large.", nameof(verifierPrivateKey));
        }

        if (challenge.ExpiresAt <= clock.GetUtcNow())
        {
            throw new ArgumentException("The verifier's one-time challenge expired while signing.", nameof(challenge));
        }

        return signed;
    }

    /// <summary>
    /// Verify the actual signed verifier request, independently pinned verifier
    /// DID, HTTPS callback, credential type and subject context before the wallet
    /// obtains informed, full-disclosure consent from its human user.
    /// </summary>
    public static bool TryReadSignedRequest(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri,
        TimeProvider clock, out JwtVcJsonDirectPostRequest? request)
    {
        ArgumentNullException.ThrowIfNull(requestJwt);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        ArgumentNullException.ThrowIfNull(clock);
        request = null;

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedVerifierDid, out var verifierKey) ||
            !IsHttpsEndpoint(expectedResponseUri) ||
            !IsValidCredentialType(expectedCredentialType) ||
            !IsValidContext(expectedSubjectContextUri))
        {
            return false;
        }

        string expectedClientId = "decentralized_identifier:" + expectedVerifierDid;
        string kid = expectedVerifierDid + "#" + expectedVerifierDid["did:key:".Length..];
        if (!StrictJwtReader.TryRead(requestJwt, "oauth-authz-req+jwt",
                MaximumRequestLength, out var payload, kid) ||
            payload.EnumerateObject().Count() != 13 ||
            !StrictJwtReader.TryGetString(payload, "client_id", out var clientId) ||
            !string.Equals(clientId, expectedClientId, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "response_type", out var responseType) ||
            responseType != "vp_token" ||
            !StrictJwtReader.TryGetString(payload, "response_mode", out var responseMode) ||
            responseMode != "direct_post" ||
            !StrictJwtReader.TryGetString(payload, "response_uri", out var responseUri) ||
            !string.Equals(responseUri, expectedResponseUri.OriginalString, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) ||
            !PresentationChallengePolicy.IsValidNonce(nonce) ||
            !StrictJwtReader.TryGetString(payload, "state", out var state) ||
            !string.Equals(state, nonce, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) ||
            audience != RequestAudience ||
            !StrictJwtReader.TryGetString(payload, "herossid_trusted_issuer_did", out var issuerDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !StrictJwtReader.TryGetString(payload, "herossid_subject_context_uri", out var context) ||
            !string.Equals(context, expectedSubjectContextUri.AbsoluteUri, StringComparison.Ordinal) ||
            !payload.TryGetProperty("dcql_query", out var query) ||
            !IsSupportedQuery(query, expectedCredentialType) ||
            !payload.TryGetProperty("client_metadata", out var metadata) ||
            !IsSupportedMetadata(metadata) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "exp", out var expiresAt))
        {
            return false;
        }

        decimal current = PresentationChallengePolicy.NumericDate(clock.GetUtcNow());
        if (issuedAt > current || expiresAt <= current || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 300 ||
            expiresAt - current > (decimal)InMemoryPresentationChallengeStore.MaximumLifetime.TotalSeconds ||
            !Ed25519JwtSigner.VerifySignedJwt(requestJwt, verifierKey))
        {
            return false;
        }

        request = new JwtVcJsonDirectPostRequest(
            new PresentationChallenge
            {
                Nonce = nonce,
                Audience = clientId,
                TrustedIssuerDid = issuerDid,
                ExpiresAt = DateTimeOffset.UnixEpoch.AddTicks((long)(expiresAt * TimeSpan.TicksPerSecond))
            },
            clientId, new Uri(responseUri, UriKind.Absolute), expectedCredentialType);
        return true;
    }

    /// <summary>
    /// After the application has displayed every disclosed claim and obtained
    /// consent, sign the actual holder VP and encode a standard direct_post form.
    /// Send ONLY to the callback authenticated by TryReadSignedRequest.
    /// </summary>
    public static string CreateHolderResponseForm(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, string expectedCredentialType, Uri expectedSubjectContextUri,
        string credentialJwt, string holderDid, byte[] holderSeed, TimeProvider clock)
    {
        if (!TryReadSignedRequest(requestJwt, expectedVerifierDid, expectedResponseUri,
                expectedCredentialType, expectedSubjectContextUri, clock, out var request) ||
            request is null)
        {
            throw new ArgumentException("Signed verifier request or independent holder policy was not authenticated.", nameof(requestJwt));
        }

        // Authenticate the actual issuer JWT and holder key in the existing VP
        // implementation; never re-sign or rewrite the issuer's credential.
        string presentation = JwtVcJsonPresentation.CreateForAuthenticatedChallenge(
            request.Challenge, credentialJwt, expectedCredentialType, expectedSubjectContextUri,
            holderDid, holderSeed, clock);

        string tokenJson = JsonSerializer.Serialize(new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            [CredentialQueryId] = [presentation]
        });
        string form = "vp_token=" + Uri.EscapeDataString(tokenJson) +
            "&state=" + Uri.EscapeDataString(request.Challenge.Nonce);
        if (form.Length > MaximumResponseLength)
        {
            throw new ArgumentException("Signed holder presentation exceeds the direct_post profile limit.", nameof(credentialJwt));
        }

        return form;
    }

    /// <summary>
    /// Validate a bounded direct_post body against verifier-owned tenant,
    /// policy, single-use nonce and real issuer/holder Ed25519 signatures.
    /// SignedButStatusUnchecked is not current non-revocation, identity
    /// verification, end-user consent or business authority.
    /// </summary>
    public static JwtVcJsonPresentationCheckResult CheckResponseForm(string form,
        Guid verifierTenantId, string expectedClientId, string expectedNonce,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        IPresentationChallengeStore challenges, TimeProvider clock, out JsonElement verifiedSubject)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;

        if (string.IsNullOrWhiteSpace(form) || form.Length > MaximumResponseLength ||
            !PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedClientId, expectedNonce))
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in form.Split('&'))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0)
            {
                return JwtVcJsonPresentationCheckResult.Invalid;
            }

            string? key = WebUtility.UrlDecode(pair[..separator]);
            string? value = WebUtility.UrlDecode(pair[(separator + 1)..]);
            if (key is null || value is null || !values.TryAdd(key, value))
            {
                return JwtVcJsonPresentationCheckResult.Invalid;
            }
        }

        if (values.Count != 2 ||
            !values.TryGetValue("state", out var state) ||
            !string.Equals(state, expectedNonce, StringComparison.Ordinal) ||
            !values.TryGetValue("vp_token", out var token) ||
            token.Length > MaximumResponseLength)
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }

        try
        {
            using var document = JsonDocument.Parse(token, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
                !root.TryGetProperty(CredentialQueryId, out var entries) ||
                entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() != 1 ||
                entries[0].ValueKind != JsonValueKind.String)
            {
                return JwtVcJsonPresentationCheckResult.Invalid;
            }

            string presentation = entries[0].GetString()!;
            if (!StrictJwtReader.IsCanonicalCompact(presentation, MaximumPresentationLength))
            {
                return JwtVcJsonPresentationCheckResult.Invalid;
            }

            return JwtVcJsonPresentation.Check(presentation, verifierTenantId,
                expectedClientId, expectedNonce, expectedCredentialType,
                expectedSubjectContextUri, challenges, clock, out verifiedSubject);
        }
        catch (JsonException)
        {
            return JwtVcJsonPresentationCheckResult.Invalid;
        }
    }

    private static bool IsSupportedQuery(JsonElement query, string credentialType)
    {
        if (query.ValueKind != JsonValueKind.Object || query.EnumerateObject().Count() != 1 ||
            !query.TryGetProperty("credentials", out var credentials) ||
            credentials.ValueKind != JsonValueKind.Array || credentials.GetArrayLength() != 1)
        {
            return false;
        }

        var credential = credentials[0];
        if (credential.ValueKind != JsonValueKind.Object || credential.EnumerateObject().Count() != 4 ||
            !StrictJwtReader.TryGetString(credential, "id", out var id) ||
            id != CredentialQueryId ||
            !StrictJwtReader.TryGetString(credential, "format", out var format) ||
            format != "jwt_vc_json" ||
            !credential.TryGetProperty("require_cryptographic_holder_binding", out var binding) ||
            binding.ValueKind != JsonValueKind.True ||
            !credential.TryGetProperty("meta", out var meta) ||
            meta.ValueKind != JsonValueKind.Object || meta.EnumerateObject().Count() != 1 ||
            !meta.TryGetProperty("type_values", out var values) ||
            values.ValueKind != JsonValueKind.Array || values.GetArrayLength() != 1)
        {
            return false;
        }

        var types = values[0];
        return types.ValueKind == JsonValueKind.Array && types.GetArrayLength() == 2 &&
            types[0].ValueKind == JsonValueKind.String && types[1].ValueKind == JsonValueKind.String &&
            string.Equals(types[0].GetString(), "VerifiableCredential", StringComparison.Ordinal) &&
            string.Equals(types[1].GetString(), credentialType, StringComparison.Ordinal);
    }

    private static bool IsSupportedMetadata(JsonElement metadata)
    {
        if (metadata.ValueKind != JsonValueKind.Object || metadata.EnumerateObject().Count() != 1 ||
            !metadata.TryGetProperty("vp_formats_supported", out var formats) ||
            formats.ValueKind != JsonValueKind.Object || formats.EnumerateObject().Count() != 1 ||
            !formats.TryGetProperty("jwt_vc_json", out var format) ||
            format.ValueKind != JsonValueKind.Object || format.EnumerateObject().Count() != 1 ||
            !format.TryGetProperty("alg_values", out var algorithms) ||
            algorithms.ValueKind != JsonValueKind.Array || algorithms.GetArrayLength() != 1)
        {
            return false;
        }

        return algorithms[0].ValueKind == JsonValueKind.String &&
            string.Equals(algorithms[0].GetString(), "EdDSA", StringComparison.Ordinal);
    }

    private static bool IsHttpsEndpoint(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        uri.OriginalString.Length <= PresentationChallengePolicy.MaximumIdentifierLength &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;

    private static bool IsValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        uri.AbsoluteUri.Length <= PresentationChallengePolicy.MaximumIdentifierLength;

    private static bool IsValidCredentialType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        !string.Equals(type, "VerifiableCredential", StringComparison.Ordinal);
}
