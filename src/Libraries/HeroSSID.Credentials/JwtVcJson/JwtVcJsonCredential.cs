using System.Globalization;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.JwtVcJson;

/// <summary>
/// Strict opt-in W3C VC Data Model 1.1 JWT-VC credential profile as used by
/// OpenID4VP 1.0's jwt_vc_json format. This is NOT VCDM 2.0 JOSE, the legacy
/// HeroSSID vc.context representation, an OpenID4VP exchange, or a wallet.
/// </summary>
public static class JwtVcJsonCredential
{
    private const string BaseContext = "https://www.w3.org/2018/credentials/v1";
    private const string BaseType = "VerifiableCredential";
    // W3C VC Data Model 1.1 Recommendation §6.3.1 requires typ=JWT if present.
    // Retain verification of the previously issued HeroSSID vc+jwt header as a
    // bounded legacy input, without presenting it as VC1.1-conformant output.
    private const string JwtType = "JWT";
    private const string LegacyJwtType = "vc+jwt";
    private const int MaximumJwtLength = 65_536;
    private const int MaximumSubjectBytes = 16_384;
    private const long MaximumValiditySeconds = 900;

    /// <summary>
    /// Opt-in issuance of a VC Data Model 1.1 credential with an issuer-assigned
    /// HTTPS identifier in the signed JWT jti claim. This identifier is not
    /// an authorization or identity attestation and is never dereferenced.
    /// </summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil, Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, credentialId);
    }

    /// <summary>
    /// Verify issuer-signed claims and expose the exact authenticated JWT jti
    /// only after every verification condition succeeds, or null on failure.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject, out string? verifiedCredentialId)
        => TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject, out verifiedCredentialId);

    /// <summary>
    /// Sign a short-lived, fully disclosed JWT VC 1.1 with the issuer's own Ed25519 seed.
    /// Subject vocabulary is controlled by a versioned HTTPS context pinned by the verifier.
    /// A signature proves issuer-key control, NOT real-world identity, authorization or
    /// control of the holder's key. Caller must protect and erase the seed.
    /// </summary>
    public static string Create(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil, null);

    /// <summary>
    /// Opt-in VC1.1 JWT issuance retaining the exact caller-supplied validity
    /// instants as RFC 7519 NumericDate fractions down to 100 nanoseconds.
    /// Unlike Create, this does not round inward to whole seconds. The original
    /// issuer controls the seed; holder control and business authority are separate.
    /// </summary>
    public static string CreateWithExactValidity(string issuerDid, string holderDid,
        string credentialType, Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil) =>
        CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil,
            null, exactValidity: true);

    /// <summary>
    /// Exact-validity issuance with an optional portable HTTPS credential ID
    /// signed into JWT jti, not a remotely trusted issuer or authorization.
    /// </summary>
    public static string CreateWithExactValidity(string issuerDid, string holderDid,
        string credentialType, Uri subjectContextUri, JsonElement credentialSubject,
        byte[] issuerPrivateKey, DateTimeOffset validFrom, DateTimeOffset validUntil,
        Uri credentialId)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        return CreateCore(issuerDid, holderDid, credentialType, subjectContextUri,
            credentialSubject, issuerPrivateKey, validFrom, validUntil,
            credentialId, exactValidity: true);
    }

    private static string CreateCore(string issuerDid, string holderDid, string credentialType,
        Uri subjectContextUri, JsonElement credentialSubject, byte[] issuerPrivateKey,
        DateTimeOffset validFrom, DateTimeOffset validUntil, Uri? credentialId,
        bool exactValidity = false)
    {
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(holderDid);
        ArgumentNullException.ThrowIfNull(credentialType);
        ArgumentNullException.ThrowIfNull(subjectContextUri);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        // Preserve the previous whole-second Create contract: round the start
        // inward UP and the end inward DOWN. Only explicit exact-validity calls
        // retain the 100ns DateTimeOffset instants as signed JWT NumericDates.
        // Neither profile ever widens the caller's requested interval.
        decimal issued = exactValidity ? NumericDate(validFrom) : validFrom.ToUnixTimeSeconds();
        if (!exactValidity && validFrom.UtcTicks % TimeSpan.TicksPerSecond != 0)
        {
            issued++;
        }

        decimal expires = exactValidity ? NumericDate(validUntil) : validUntil.ToUnixTimeSeconds();
        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(issuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(holderDid, out _) ||
            !ValidType(credentialType) ||
            !ValidContext(subjectContextUri) ||
            (credentialId is not null && !ValidCredentialId(credentialId)) ||
            issuerPrivateKey.Length != 32 ||
            issuerPrivateKey.All(static b => b == 0) ||
            issued < 0 || expires <= issued ||
            expires - issued > MaximumValiditySeconds ||
            // VC1.1 allows one object or an array containing exactly one object.
            // Keep the exact wire representation; never normalize an
            // ambiguous/multiple-subject array or rewrite a conflicting id.
            !HasIssuableSubject(credentialSubject, holderDid) ||
            StrictJwtReader.HasEmbeddedContext(credentialSubject) ||
            Encoding.UTF8.GetByteCount(credentialSubject.GetRawText()) > MaximumSubjectBytes)
        {
            throw new ArgumentException("Invalid JWT VC 1.1 key, context, subject, vocabulary or bounded validity.");
        }

        string header = JsonSerializer.Serialize(new
        {
            alg = "EdDSA",
            typ = JwtType,
            kid = KeyId(issuerDid)
        });
        var payloadClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = issuerDid,
            ["sub"] = holderDid,
            ["iat"] = issued,
            ["nbf"] = issued,
            ["exp"] = expires
        };
        if (credentialId is not null)
        {
            payloadClaims["jti"] = credentialId.AbsoluteUri;
        }

        payloadClaims["vc"] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["@context"] = new[] { BaseContext, subjectContextUri.AbsoluteUri },
            ["type"] = new[] { BaseType, credentialType },
            ["credentialSubject"] = credentialSubject
        };
        string payload = JsonSerializer.Serialize(payloadClaims);
        string signed = Ed25519JwtSigner.CreateSignedJwt(header, payload, issuerPrivateKey);

        // Check the actual cryptographic result against the self-certifying issuer DID,
        // including unique nested JSON properties. Wrong-key or malformed output
        // must never escape this API as a purported credential.
        if (signed.Length > MaximumJwtLength ||
            !TryVerify(signed, issuerDid, holderDid, credentialType,
                subjectContextUri,
                exactValidity ? validFrom : DateTimeOffset.FromUnixTimeSeconds((long)issued),
                out _))
        {
            throw new ArgumentException("The seed does not control the issuer DID or the VC is ambiguous/oversized.",
                nameof(issuerPrivateKey));
        }

        return signed;
    }

    /// <summary>
    /// Independently verify the actual Ed25519 issuer signature and pinned issuer,
    /// holder, type, HTTPS vocabulary and 15-minute validity, before releasing claims.
    /// Also accepts independently signed VC1.1 JWTs with typ=JWT, an omitted
    /// optional kid, bounded HTTPS jti and no iat (or iat preceding nbf by at
    /// most 15 minutes). A present kid MUST match the pinned issuer. Existing
    /// HeroSSID typ=vc+jwt credentials remain readable as legacy input only.
    /// Does NOT establish holder possession, consent, revocation or business authority.
    /// </summary>
    public static bool TryVerify(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject) =>
        TryVerifyCore(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType,
            expectedSubjectContextUri, now, out verifiedSubject, out _);

    private static bool TryVerifyCore(string jwt, string trustedIssuerDid, string expectedHolderDid,
        string expectedCredentialType, Uri expectedSubjectContextUri,
        DateTimeOffset now, out JsonElement verifiedSubject, out string? verifiedCredentialId)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(expectedSubjectContextUri);
        verifiedSubject = default;
        verifiedCredentialId = null;

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(trustedIssuerDid, out var issuerPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedHolderDid, out _) ||
            !ValidType(expectedCredentialType) ||
            !ValidContext(expectedSubjectContextUri) ||
            !TryReadSupportedCredentialJwt(jwt, trustedIssuerDid, out var payload, out bool isNormativeJwt) ||
            !HasSupportedClaims(payload) ||
            !Ed25519JwtSigner.VerifySignedJwt(jwt, issuerPublicKey) ||
            !StrictJwtReader.TryGetString(payload, "iss", out var signedIssuer) ||
            !string.Equals(signedIssuer, trustedIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(payload, "sub", out var signedSubject) ||
            !string.Equals(signedSubject, expectedHolderDid, StringComparison.Ordinal) ||
            !TryGetSignedNumericDate(payload, "nbf", isNormativeJwt, out var notBefore) ||
            !TryGetSignedNumericDate(payload, "exp", isNormativeJwt, out var expires) ||
            !HasValidOptionalIssuedAt(payload, notBefore, isNormativeJwt) ||
            !HasValidOptionalCredentialId(payload) ||
            expires <= notBefore || expires - notBefore > MaximumValiditySeconds ||
            notBefore > NumericDate(now) || expires <= NumericDate(now) ||
            !payload.TryGetProperty("vc", out var vc) ||
            vc.ValueKind != JsonValueKind.Object ||
            !HasCompatibleEmbeddedVcMetadata(vc, payload, trustedIssuerDid,
                notBefore, expires, isNormativeJwt) ||
            !HasExactArray(vc, "@context", BaseContext, expectedSubjectContextUri.AbsoluteUri) ||
            !HasExactArray(vc, "type", BaseType, expectedCredentialType) ||
            !vc.TryGetProperty("credentialSubject", out var encodedSubject) ||
            !TryReadVerifiedSubject(encodedSubject, expectedHolderDid, isNormativeJwt, out var subject))
        {
            return false;
        }

        verifiedSubject = subject.Clone();
        verifiedCredentialId = payload.TryGetProperty("jti", out var identifier)
            ? identifier.GetString()
            : null;
        return true;
    }

    private static bool TryReadSupportedCredentialJwt(string jwt, string issuerDid,
        out JsonElement payload, out bool isNormativeJwt)
    {
        // W3C VC1.1 REC §6.3.1 makes typ optional (if present, JWT), and
        // kid optional. Both still require an independently pinned Ed25519
        // issuer; the legacy vc+jwt form keeps its mandatory kid and typ. The
        // verifier-supplied did:key always supplies the signature key.
        // Legacy vc+jwt MUST continue to have the exact issuer kid.
        isNormativeJwt =
            StrictJwtReader.TryRead(jwt, JwtType, MaximumJwtLength,
                out payload, KeyId(issuerDid), allowMissingType: true) ||
            StrictJwtReader.TryRead(jwt, JwtType, MaximumJwtLength,
                out payload, allowMissingType: true);
        return isNormativeJwt ||
            StrictJwtReader.TryRead(jwt, LegacyJwtType, MaximumJwtLength,
                out payload, KeyId(issuerDid));
    }

    private static bool TryReadVerifiedSubject(JsonElement encodedSubject, string holderDid,
        bool isNormativeJwt, out JsonElement subject)
    {
        subject = default;
        if (encodedSubject.ValueKind == JsonValueKind.Object)
        {
            subject = encodedSubject;
        }
        else if (isNormativeJwt &&
            encodedSubject.ValueKind == JsonValueKind.Array &&
            encodedSubject.GetArrayLength() == 1 &&
            encodedSubject[0].ValueKind == JsonValueKind.Object)
        {
            // VC1.1 allows array-form subjects. This deliberately supports
            // exactly one, and returns that unchanged signed object, avoiding
            // ambiguity for callers of the existing single-subject SDK.
            subject = encodedSubject[0];
        }
        else
        {
            return false;
        }

        // Check the full original encoded subject, not only the selected view,
        // so an array wrapper cannot evade size or scoped-context restrictions.
        if (!HasBoundSubject(subject, holderDid, isNormativeJwt) ||
            StrictJwtReader.HasEmbeddedContext(encodedSubject) ||
            Encoding.UTF8.GetByteCount(encodedSubject.GetRawText()) > MaximumSubjectBytes)
        {
            subject = default;
            return false;
        }

        return true;
    }

    private static bool HasIssuableSubject(JsonElement encodedSubject, string holderDid)
    {
        JsonElement subject = encodedSubject;
        if (encodedSubject.ValueKind == JsonValueKind.Array)
        {
            if (encodedSubject.GetArrayLength() != 1 ||
                encodedSubject[0].ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            subject = encodedSubject[0];
        }

        return subject.ValueKind == JsonValueKind.Object &&
            HasBoundSubject(subject, holderDid, isNormativeJwt: true);
    }

    private static bool HasBoundSubject(JsonElement subject, string holderDid, bool isNormativeJwt)
    {
        // JWT sub represents credentialSubject.id in VC1.1. The duplicate
        // nested field MAY be omitted for the normative JWT only. If explicitly
        // present, including null or an empty string, it MUST match the independently
        // pinned holder; never let a signed conflict be silently overwritten.
        if (subject.TryGetProperty("id", out _))
        {
            return HasSubjectId(subject, holderDid);
        }

        return isNormativeJwt;
    }

    // W3C VC 1.1 maps the credential id into JWT jti. OpenID4VP's
    // jwt_vc_json example omits iat altogether. Recognize only these
    // two known optional claims; fail closed on any other payload members.
    private static bool HasSupportedClaims(JsonElement payload) =>
        payload.EnumerateObject().Count() == 5 +
        (payload.TryGetProperty("iat", out _) ? 1 : 0) +
        (payload.TryGetProperty("jti", out _) ? 1 : 0);

    // RFC 7519 allows fractional NumericDates. Only accept exact 100ns
    // instants; keep older nonstandard vc+jwt payloads integer-only.
    internal static bool TryGetSignedNumericDate(
        JsonElement claims, string name, bool normative, out decimal seconds)
    {
        seconds = 0;
        if (!normative)
        {
            if (!StrictJwtReader.TryGetTimestamp(claims, name, out long integral))
            {
                return false;
            }

            seconds = integral;
            return true;
        }

        if (!claims.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        // JsonElement.TryGetDecimal may round a long JSON coefficient before
        // we inspect it (e.g. ...00000000000000000001 becomes a whole second).
        // Check the ORIGINAL signed numeric lexeme for nonzero sub-tick
        // digits, including scientific notation, BEFORE decimal conversion.
        string raw = value.GetRawText();
        if (raw.Length is < 1 or > 80 || raw[0] == '-')
        {
            return false;
        }

        int exponentSeparator = raw.IndexOfAny('e', 'E');
        string mantissa = exponentSeparator < 0 ? raw : raw[..exponentSeparator];
        int exponent = 0;
        if (exponentSeparator >= 0 &&
            (!int.TryParse(raw.AsSpan(exponentSeparator + 1),
                NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture,
                out exponent) || exponent is < -1000 or > 1000))
        {
            return false;
        }

        int point = mantissa.IndexOf('.', StringComparison.Ordinal);
        int decimalPosition = (point < 0 ? mantissa.Length : point) + exponent;
        int digitIndex = 0;
        foreach (char digit in mantissa)
        {
            if (digit == '.')
            {
                continue;
            }

            // Decimal position - digit index - 1 is this digit's power of 10.
            // Any nonzero digit at 10^-8 or smaller is not exactly representable
            // by a .NET DateTimeOffset; never round it into an accepted instant.
            if (decimalPosition - digitIndex - 1 < -7 && digit != '0')
            {
                return false;
            }

            digitIndex++;
        }

        if (!decimal.TryParse(raw, NumberStyles.Float,
                CultureInfo.InvariantCulture, out seconds) ||
            seconds < 0 || seconds >= 253402300800m)
        {
            return false;
        }

        decimal ticks = seconds * TimeSpan.TicksPerSecond;
        return ticks == decimal.Truncate(ticks);
    }

    internal static bool HasValidOptionalIssuedAt(
        JsonElement claims, decimal notBefore, bool normative) =>
        !claims.TryGetProperty("iat", out _) ||
        (TryGetSignedNumericDate(claims, "iat", normative, out decimal issued) &&
            issued <= notBefore && issued >= notBefore - MaximumValiditySeconds);

    private static decimal NumericDate(DateTimeOffset instant) =>
        (decimal)(instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) /
        TimeSpan.TicksPerSecond;

    private static bool HasValidOptionalCredentialId(JsonElement payload)
    {
        if (!payload.TryGetProperty("jti", out _))
        {
            return true;
        }

        // Signed identifiers are never dereferenced or treated as authority.
        return StrictJwtReader.TryGetString(payload, "jti", out string id) &&
            id.Length <= 2_048 &&
            Uri.TryCreate(id, UriKind.Absolute, out Uri? uri) &&
            ValidCredentialId(uri);
    }

    private static bool ValidCredentialId(Uri uri) =>
        uri.IsAbsoluteUri &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        uri.UserInfo.Length == 0 &&
        uri.AbsoluteUri.Length <= 2_048;

    /// <summary>
    /// W3C VC1.1 REC §6.3.1 permits registered JWT claims instead of, or
    /// in addition to, the equivalent VC properties. Accept only redundant
    /// fields that are semantically identical to the authenticated JWT claims.
    /// Untrusted metadata never enrolls issuers, replaces the signed subject,
    /// grants authority or overrides verifier policy. Historical vc+jwt stays
    /// on its original strict three-member VC shape.
    /// </summary>
    internal static bool HasCompatibleEmbeddedVcMetadata(
        JsonElement vc, JsonElement payload, string pinnedIssuerDid,
        decimal signedNotBefore, decimal signedExpires, bool isNormativeJwt)
    {
        bool hasIssuer = vc.TryGetProperty("issuer", out var embeddedIssuer);
        bool hasId = vc.TryGetProperty("id", out _);
        bool hasIssuance = vc.TryGetProperty("issuanceDate", out _);
        bool hasExpiration = vc.TryGetProperty("expirationDate", out _);
        int metadataCount = (hasIssuer ? 1 : 0) + (hasId ? 1 : 0) +
            (hasIssuance ? 1 : 0) + (hasExpiration ? 1 : 0);

        if (vc.EnumerateObject().Count() != 3 + metadataCount ||
            (!isNormativeJwt && metadataCount != 0))
        {
            return false;
        }

        if (hasIssuer)
        {
            bool matchesIssuer = embeddedIssuer.ValueKind switch
            {
                JsonValueKind.String =>
                    string.Equals(embeddedIssuer.GetString(), pinnedIssuerDid,
                        StringComparison.Ordinal),
                JsonValueKind.Object =>
                    embeddedIssuer.EnumerateObject().Count() == 1 &&
                    StrictJwtReader.TryGetString(embeddedIssuer, "id", out string issuerId) &&
                    string.Equals(issuerId, pinnedIssuerDid, StringComparison.Ordinal),
                _ => false
            };
            if (!matchesIssuer)
            {
                return false;
            }
        }

        if (hasId &&
            (!StrictJwtReader.TryGetString(payload, "jti", out string signedId) ||
             !StrictJwtReader.TryGetString(vc, "id", out string embeddedId) ||
             !string.Equals(embeddedId, signedId, StringComparison.Ordinal)))
        {
            return false;
        }

        return (!hasIssuance || HasMatchingXmlDateTime(vc, "issuanceDate", signedNotBefore)) &&
            (!hasExpiration || HasMatchingXmlDateTime(vc, "expirationDate", signedExpires));
    }

    private static bool HasMatchingXmlDateTime(JsonElement vc, string name, decimal signedEpoch)
    {
        if (!StrictJwtReader.TryGetString(vc, name, out string dateTime) ||
            dateTime.Length > 64 || dateTime.Length < 20)
        {
            return false;
        }

        // XmlConvert's AllXsd parser also accepts date-only values, which
        // must not be confused with VC1.1's required xsd:dateTime lexical
        // form. Check a *complete* calendar date, time and explicit zone first.
        ReadOnlySpan<char> value = dateTime.AsSpan();
        bool utc = value[^1] == 'Z';
        int zoneLength = utc ? 1 : 6;
        int end = value.Length - zoneLength;
        if (end < 19 ||
            (utc ? value[^1] != 'Z' :
                (value[^6] != '+' && value[^6] != '-') || value[^3] != ':' ||
                !AllAsciiDigits(value.Slice(value.Length - 5, 2)) ||
                !AllAsciiDigits(value.Slice(value.Length - 2, 2))) ||
            value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
            value[13] != ':' || value[16] != ':' ||
            !AllAsciiDigits(value[..4]) ||
            !AllAsciiDigits(value.Slice(5, 2)) ||
            !AllAsciiDigits(value.Slice(8, 2)) ||
            !AllAsciiDigits(value.Slice(11, 2)) ||
            !AllAsciiDigits(value.Slice(14, 2)) ||
            !AllAsciiDigits(value.Slice(17, 2)) ||
            // Validate all fractional digits and reject any nonzero sub-tick
            // tail before XmlConvert can round a different instant.
            (end > 19 &&
                (value[19] != '.' || end == 20 ||
                 !AllAsciiDigits(value.Slice(20, end - 20)) ||
                 (end > 27 && !AllZeroDigits(value.Slice(27, end - 27))))))
        {
            return false;
        }

        bool isEndOfDay = value[11] == '2' && value[12] == '4';
        if (isEndOfDay &&
            (value[14] != '0' || value[15] != '0' ||
             value[17] != '0' || value[18] != '0' ||
             (end > 19 && !AllZeroDigits(value.Slice(20, end - 20)))))
        {
            return false;
        }

        try
        {
            // XML Schema 1.1 permits 24:00:00 to denote the following
            // midnight. XmlConvert rejects this valid lexical representation;
            // normalize only this exact end-of-day case, then apply the offset.
            DateTimeOffset parsed = isEndOfDay
                ? System.Xml.XmlConvert.ToDateTimeOffset(
                    string.Concat(dateTime.AsSpan(0, 11), "00",
                        dateTime.AsSpan(13))).AddDays(1)
                : System.Xml.XmlConvert.ToDateTimeOffset(dateTime);
            return (decimal)(parsed.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) ==
                signedEpoch * TimeSpan.TicksPerSecond;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool AllAsciiDigits(ReadOnlySpan<char> value)
    {
        foreach (char digit in value)
        {
            if (digit is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool AllZeroDigits(ReadOnlySpan<char> value)
    {
        foreach (char digit in value)
        {
            if (digit != '0')
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasExactArray(JsonElement element, string name, string first, string second)
    {
        if (!element.TryGetProperty(name, out var values) ||
            values.ValueKind != JsonValueKind.Array || values.GetArrayLength() != 2)
        {
            return false;
        }

        return values[0].ValueKind == JsonValueKind.String &&
            values[1].ValueKind == JsonValueKind.String &&
            string.Equals(values[0].GetString(), first, StringComparison.Ordinal) &&
            string.Equals(values[1].GetString(), second, StringComparison.Ordinal);
    }

    private static bool HasSubjectId(JsonElement subject, string holderDid) =>
        StrictJwtReader.TryGetString(subject, "id", out var id) &&
        string.Equals(id, holderDid, StringComparison.Ordinal);

    private static bool ValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Fragment) &&
        uri.AbsoluteUri.Length <= 2048;

    private static bool ValidType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        !string.Equals(type, BaseType, StringComparison.Ordinal);

    private static string KeyId(string issuerDid) =>
        issuerDid + "#" + issuerDid["did:key:".Length..];
}
