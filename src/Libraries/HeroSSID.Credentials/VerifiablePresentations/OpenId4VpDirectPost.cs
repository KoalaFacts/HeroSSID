using System.Net;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>A verified signed OpenID4VP 1.0 request in the supported single-credential profile.</summary>
public sealed record OpenId4VpDirectPostRequest(
    PresentationChallenge Challenge, string ClientId, Uri ResponseUri);

/// <summary>
/// A deliberately bounded OpenID4VP 1.0 request/response transport profile using
/// signed JAR, decentralized_identifier:did:key, herossid_vc_jwt and direct_post.
/// It does not implement discovery, request_uri, encryption, DCQL alternatives or
/// third-party wallet interoperability. Signatures do not establish business authority.
/// </summary>
public static class OpenId4VpDirectPost
{
    private const int MaximumRequestLength = 16_384;
    private const int MaximumResponseLength = 180_000;
    private const string RequestAudience = "https://self-issued.me/v2";
    private const string CredentialQueryId = "herossid_vc";
    private const string DcqlJson = "{\"credentials\":[{\"id\":\"herossid_vc\",\"format\":\"herossid_vc_jwt\",\"require_cryptographic_holder_binding\":true,\"meta\":{\"type_values\":[[\"VerifiableCredential\"]]}}]}";
    private const string MetadataJson = "{\"vp_formats_supported\":{\"herossid_vc_jwt\":{\"alg_values\":[\"EdDSA\"]}}}";
    private const string PresentationHeader = "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}";

    /// <summary>
    /// Signs an already-issued, retained verifier challenge as an OpenID4VP 1.0
    /// Request Object passed by value. Client ID is decentralized_identifier:did:key.
    /// The caller owns and must erase the private seed after use.
    /// </summary>
    public static string CreateSignedRequest(PresentationChallenge challenge, string verifierDid,
        byte[] verifierPrivateKey, Uri responseUri, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(verifierDid);
        ArgumentNullException.ThrowIfNull(verifierPrivateKey);
        ArgumentNullException.ThrowIfNull(responseUri);
        ArgumentNullException.ThrowIfNull(clock);

        var now = clock.GetUtcNow();
        string clientId = "decentralized_identifier:" + verifierDid;
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(verifierDid, out var verifierKey) ||
            verifierPrivateKey.Length != 32 || verifierPrivateKey.All(static value => value == 0) ||
            !IsHttpsEndpoint(responseUri) ||
            !string.Equals(challenge.Audience, clientId, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.IsValidNonce(challenge.Nonce) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(challenge.TrustedIssuerDid, out _) ||
            challenge.ExpiresAt <= now ||
            challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("A live verifier-owned challenge, Ed25519 key and HTTPS callback are required.", nameof(challenge));
        }

        using var dcql = JsonDocument.Parse(DcqlJson);
        using var metadata = JsonDocument.Parse(MetadataJson);
        var payload = JsonSerializer.Serialize(new
        {
            client_id = clientId,
            response_type = "vp_token",
            response_mode = "direct_post",
            response_uri = responseUri.OriginalString,
            nonce = challenge.Nonce,
            state = challenge.Nonce,
            dcql_query = dcql.RootElement,
            client_metadata = metadata.RootElement,
            herossid_trusted_issuer_did = challenge.TrustedIssuerDid,
            aud = RequestAudience,
            iat = PresentationChallengePolicy.NumericDate(now),
            exp = PresentationChallengePolicy.NumericDate(challenge.ExpiresAt)
        });
        string keyId = verifierDid + "#" + verifierDid["did:key:".Length..];
        string header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = "oauth-authz-req+jwt", kid = keyId });
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, verifierPrivateKey);
        if (signed.Length > MaximumRequestLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, verifierKey))
        {
            throw new ArgumentException("Verifier seed does not control the DID or request exceeds the size limit.", nameof(verifierPrivateKey));
        }

        if (challenge.ExpiresAt <= clock.GetUtcNow())
        {
            throw new ArgumentException("Verifier challenge expired during signing.", nameof(challenge));
        }

        return signed;
    }

    /// <summary>
    /// Authenticates the exact request, the pinned verifier DID and separately
    /// pinned HTTPS callback before the holder inspects and consents to disclosure.
    /// A DID or URL supplied only by the untrusted request is never a trust anchor.
    /// </summary>
    public static bool TryReadSignedRequest(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, TimeProvider clock, out OpenId4VpDirectPostRequest? request)
    {
        ArgumentNullException.ThrowIfNull(requestJwt);
        ArgumentNullException.ThrowIfNull(expectedResponseUri);
        ArgumentNullException.ThrowIfNull(clock);
        request = null;
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedVerifierDid, out var verifierKey) ||
            !IsHttpsEndpoint(expectedResponseUri))
        {
            return false;
        }

        string expectedKid = expectedVerifierDid + "#" + expectedVerifierDid["did:key:".Length..];
        string expectedClientId = "decentralized_identifier:" + expectedVerifierDid;
        if (!StrictJwtReader.TryRead(requestJwt, "oauth-authz-req+jwt",
                MaximumRequestLength, out var payload, expectedKid) ||
            payload.EnumerateObject().Count() != 12 ||
            !StrictJwtReader.TryGetString(payload, "client_id", out var clientId) ||
            !string.Equals(clientId, expectedClientId, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "response_type", out var responseType) ||
            responseType != "vp_token" ||
            !StrictJwtReader.TryGetString(payload, "response_mode", out var responseMode) ||
            responseMode != "direct_post" ||
            !StrictJwtReader.TryGetString(payload, "response_uri", out var callback) ||
            !string.Equals(callback, expectedResponseUri.OriginalString, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) ||
            audience != RequestAudience ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) ||
            !PresentationChallengePolicy.IsValidNonce(nonce) ||
            !StrictJwtReader.TryGetString(payload, "state", out var state) ||
            !string.Equals(state, nonce, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "herossid_trusted_issuer_did", out var issuerDid) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !payload.TryGetProperty("dcql_query", out var query) || !IsSupportedQuery(query) ||
            !payload.TryGetProperty("client_metadata", out var metadata) || !IsSupportedMetadata(metadata) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(payload, "exp", out var expiresAt))
        {
            return false;
        }

        decimal now = PresentationChallengePolicy.NumericDate(clock.GetUtcNow());
        if (issuedAt > now || expiresAt <= now || expiresAt <= issuedAt ||
            expiresAt - issuedAt > 300 ||
            expiresAt - now > (decimal)InMemoryPresentationChallengeStore.MaximumLifetime.TotalSeconds ||
            !Ed25519JwtSigner.VerifySignedJwt(requestJwt, verifierKey))
        {
            return false;
        }

        // Keep the fractional NumericDate: rejecting a rounded-down one-second
        // challenge is a correctness and availability regression.
        request = new OpenId4VpDirectPostRequest(
            new PresentationChallenge
            {
                Audience = clientId,
                Nonce = nonce,
                TrustedIssuerDid = issuerDid,
                ExpiresAt = DateTimeOffset.UnixEpoch.AddTicks((long)(expiresAt * TimeSpan.TicksPerSecond))
            },
            clientId,
            new Uri(callback, UriKind.Absolute));
        return true;
    }

    /// <summary>
    /// Creates the UTF-8 application/x-www-form-urlencoded body for direct_post.
    /// Caller MUST first display the entire credential and obtain informed consent;
    /// this SDK cannot establish human consent. Send only to the verified response URI.
    /// </summary>
    public static string CreateHolderResponseForm(string requestJwt, string expectedVerifierDid,
        Uri expectedResponseUri, string credentialJwt, string holderDid, byte[] holderPrivateKey,
        TimeProvider clock)
    {
        if (!TryReadSignedRequest(requestJwt, expectedVerifierDid, expectedResponseUri, clock, out var request) ||
            request is null)
        {
            throw new ArgumentException("The signed verifier request is not trusted or fresh.", nameof(requestJwt));
        }

        // Reuse the real issuer credential and holder-key binding checks.
        string verified = OfflinePresentationCreator.Create(
            request.Challenge, credentialJwt, holderDid, holderPrivateKey, clock);
        if (!StrictJwtReader.TryRead(verified, "vp+jwt", 131_072, out var original) ||
            !PresentationChallengePolicy.TryGetNumericDate(original, "iat", out var issuedAt) ||
            !PresentationChallengePolicy.TryGetNumericDate(original, "exp", out var expiresAt))
        {
            throw new ArgumentException("The signed holder presentation is invalid.", nameof(credentialJwt));
        }

        // Keep the existing issuer JWT unchanged (its vc.context spelling is a
        // non-standard legacy profile), but add a W3C-shaped holder envelope.
        // The enclosing OpenID4VP protocol does not certify VC conformance.
        var vp = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1" },
            ["type"] = new[] { "VerifiablePresentation" },
            ["holder"] = holderDid,
            ["verifiableCredential"] = new[] { credentialJwt }
        };
        string payload = JsonSerializer.Serialize(new
        {
            iss = holderDid,
            aud = request.ClientId,
            nonce = request.Challenge.Nonce,
            iat = issuedAt,
            exp = expiresAt,
            vp
        });
        string signed = Ed25519JwtSigner.CreateSignedJwt(PresentationHeader, payload, holderPrivateKey);
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out var holderKey) ||
            !Ed25519JwtSigner.VerifySignedJwt(signed, holderKey) ||
            signed.Length > 131_072 ||
            PresentationChallengePolicy.NumericDate(clock.GetUtcNow()) >= expiresAt)
        {
            throw new ArgumentException("Holder control, size or presentation freshness check failed.", nameof(holderPrivateKey));
        }

        var token = JsonSerializer.Serialize(new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            [CredentialQueryId] = [signed]
        });
        return "vp_token=" + Uri.EscapeDataString(token) +
            "&state=" + Uri.EscapeDataString(request.Challenge.Nonce);
    }

    /// <summary>
    /// Validates one form-encoded direct_post VP Token against the verifier's
    /// retained challenge and trusted issuer. SignedNotListed is NOT authorization,
    /// real-world identity or a guarantee of real-time non-revocation.
    /// </summary>
    public static OfflinePresentationCheckResult CheckResponseForm(string form, string snapshotJwt,
        Guid verifierTenantId, string expectedClientId, string expectedNonce,
        IPresentationChallengeStore challenges, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(clock);
        if (string.IsNullOrWhiteSpace(form) || form.Length > MaximumResponseLength ||
            !PresentationChallengePolicy.IsValidLookup(verifierTenantId, expectedClientId, expectedNonce))
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in form.Split('&'))
        {
            int equal = pair.IndexOf('=', StringComparison.Ordinal);
            if (equal < 1 || !entries.TryAdd(
                    WebUtility.UrlDecode(pair[..equal]), WebUtility.UrlDecode(pair[(equal + 1)..])))
            {
                return OfflinePresentationCheckResult.Invalid;
            }
        }

        if (entries.Count != 2 ||
            !entries.TryGetValue("state", out var state) ||
            !string.Equals(state, expectedNonce, StringComparison.Ordinal) ||
            !entries.TryGetValue("vp_token", out var vpToken) ||
            vpToken.Length > 140_000)
        {
            return OfflinePresentationCheckResult.Invalid;
        }

        try
        {
            using var document = JsonDocument.Parse(vpToken, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Count() != 1 ||
                !root.TryGetProperty(CredentialQueryId, out var array) ||
                array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != 1 ||
                array[0].ValueKind != JsonValueKind.String)
            {
                return OfflinePresentationCheckResult.Invalid;
            }

            // This transport requires the expanded VP wrapper. A legacy private
            // HeroSSID VP must not be presented as a conforming OpenID4VP response.
            string presented = array[0].GetString()!;
            if (!StrictJwtReader.TryRead(presented, "vp+jwt", 131_072, out var payload) ||
                !payload.TryGetProperty("vp", out var vp) ||
                vp.ValueKind != JsonValueKind.Object || vp.EnumerateObject().Count() != 4 ||
                !vp.TryGetProperty("@context", out _))
            {
                return OfflinePresentationCheckResult.Invalid;
            }

            return OfflinePresentationVerifier.Check(presented, snapshotJwt,
                verifierTenantId, expectedClientId, expectedNonce, challenges, clock);
        }
        catch (JsonException)
        {
            return OfflinePresentationCheckResult.Invalid;
        }
    }

    private static bool IsHttpsEndpoint(Uri? value) =>
        value is { IsAbsoluteUri: true } &&
        value.OriginalString.Length <= PresentationChallengePolicy.MaximumIdentifierLength &&
        value.Scheme == Uri.UriSchemeHttps &&
        value.Host.Length > 0 &&
        value.UserInfo.Length == 0 &&
        value.Fragment.Length == 0;

    private static bool IsSupportedQuery(JsonElement query)
    {
        if (query.ValueKind != JsonValueKind.Object || query.EnumerateObject().Count() != 1 ||
            !query.TryGetProperty("credentials", out var credentials) ||
            credentials.ValueKind != JsonValueKind.Array || credentials.GetArrayLength() != 1)
        {
            return false;
        }

        var credential = credentials[0];
        if (credential.ValueKind != JsonValueKind.Object ||
            credential.EnumerateObject().Count() != 4 ||
            !StrictJwtReader.TryGetString(credential, "id", out var id) || id != CredentialQueryId ||
            !StrictJwtReader.TryGetString(credential, "format", out var format) || format != "herossid_vc_jwt" ||
            !credential.TryGetProperty("require_cryptographic_holder_binding", out var binding) ||
            binding.ValueKind != JsonValueKind.True ||
            !credential.TryGetProperty("meta", out var meta) ||
            meta.ValueKind != JsonValueKind.Object || meta.EnumerateObject().Count() != 1 ||
            !meta.TryGetProperty("type_values", out var types) ||
            types.ValueKind != JsonValueKind.Array || types.GetArrayLength() != 1)
        {
            return false;
        }

        var entry = types[0];
        return entry.ValueKind == JsonValueKind.Array && entry.GetArrayLength() == 1 &&
            entry[0].ValueKind == JsonValueKind.String &&
            entry[0].GetString() == "VerifiableCredential";
    }

    private static bool IsSupportedMetadata(JsonElement metadata)
    {
        if (metadata.ValueKind != JsonValueKind.Object || metadata.EnumerateObject().Count() != 1 ||
            !metadata.TryGetProperty("vp_formats_supported", out var formats) ||
            formats.ValueKind != JsonValueKind.Object || formats.EnumerateObject().Count() != 1 ||
            !formats.TryGetProperty("herossid_vc_jwt", out var format) ||
            format.ValueKind != JsonValueKind.Object || format.EnumerateObject().Count() != 1 ||
            !format.TryGetProperty("alg_values", out var algorithms) ||
            algorithms.ValueKind != JsonValueKind.Array || algorithms.GetArrayLength() != 1)
        {
            return false;
        }

        return algorithms[0].ValueKind == JsonValueKind.String &&
            algorithms[0].GetString() == "EdDSA";
    }
}
