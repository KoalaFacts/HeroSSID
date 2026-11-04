using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

public sealed class JwtVcJsonCredentialTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 6, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Vocabulary = new("https://issuer.example/contexts/membership/v1");
    private readonly (byte[] Seed, string Did) _issuer = NewIdentity();
    private readonly (byte[] Seed, string Did) _holder = NewIdentity();
    private readonly (byte[] Seed, string Did) _other = NewIdentity();

    [Fact]
    public void OrganizationIssuerCanOptInToSigningDescriptiveVcIssuerMetadata()
    {
        // The existing issuer can sign a standards-shaped VC issuer object;
        // the name is only descriptive, never a verifier trust anchor.
        // Lookup keeps the test-only RED compiling before the opt-in SDK API exists.
        var issuerApi = typeof(JwtVcJsonCredential).GetMethods()
            .SingleOrDefault(method => method.Name == "CreateWithIssuerName" &&
                method.GetParameters().Length == 9);
        Assert.NotNull(issuerApi);

        using var subjectDocument = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string jwt = Assert.IsType<string>(issuerApi!.Invoke(null,
            [_issuer.Did, _holder.Did, CredentialType, Vocabulary,
                subjectDocument.RootElement, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(10),
                "Australasian Membership Office"]));

        using var payloadDocument = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        JsonElement payload = payloadDocument.RootElement;
        Assert.Equal(_issuer.Did, payload.GetProperty("iss").GetString());
        JsonElement issuer = payload.GetProperty("vc").GetProperty("issuer");
        Assert.Equal(_issuer.Did, issuer.GetProperty("id").GetString());
        Assert.Equal("Australasian Membership Office",
            issuer.GetProperty("name").GetString());
        Assert.Equal(2, issuer.EnumerateObject().Count());

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
    }

    [Fact]
    public void IssuerCreatesGenuineJwtVcJsonWithStandardContextAndIndependentVerification()
    {
        string jwt = Issue();
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        var payload = document.RootElement;
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(_issuer.Did + "#" + _issuer.Did["did:key:".Length..],
            header.RootElement.GetProperty("kid").GetString());
        Assert.Equal(_issuer.Did, payload.GetProperty("iss").GetString());
        Assert.Equal(_holder.Did, payload.GetProperty("sub").GetString());
        var vc = payload.GetProperty("vc");
        Assert.False(vc.TryGetProperty("context", out _));
        Assert.Equal("https://www.w3.org/2018/credentials/v1",
            vc.GetProperty("@context")[0].GetString());
        Assert.Equal(Vocabulary.AbsoluteUri, vc.GetProperty("@context")[1].GetString());
        Assert.Equal(CredentialType, vc.GetProperty("type")[1].GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
    }

    [Fact]
    public void OrdinaryUtcNowFractionalSecondsCanBeIssuedAndIndependentlyVerified()
    {
        // Reproduces the documented SDK example without artificial whole-second timestamps.
        var current = DateTimeOffset.UtcNow;
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string jwt = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, _issuer.Seed,
            current.AddSeconds(-1).AddTicks(1), current.AddMinutes(10));

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, current, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
    }

    [Fact]
    public void FractionalBoundsRoundInwardsAndNeverExpandTheRequestedWindow()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        DateTimeOffset requestedStart = Now.AddMilliseconds(125);
        DateTimeOffset requestedEnd = Now.AddSeconds(600).AddMilliseconds(875);
        string jwt = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, _issuer.Seed,
            requestedStart, requestedEnd);

        using var payloadDocument = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        JsonElement payload = payloadDocument.RootElement;
        long notBefore = payload.GetProperty("nbf").GetInt64();
        long expires = payload.GetProperty("exp").GetInt64();
        Assert.Equal(Now.ToUnixTimeSeconds() + 1, notBefore);
        Assert.Equal(Now.ToUnixTimeSeconds() + 600, expires);
        Assert.Equal(notBefore, payload.GetProperty("iat").GetInt64());
        Assert.True(DateTimeOffset.FromUnixTimeSeconds(notBefore) >= requestedStart);
        Assert.True(DateTimeOffset.FromUnixTimeSeconds(expires) <= requestedEnd);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMilliseconds(999), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddSeconds(1), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddSeconds(599), out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddSeconds(600), out _));
    }

    [Fact]
    public void FractionalWindowMustRemainNonemptyShortAndSignedByThePinnedIssuer()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        DateTimeOffset start = Now.AddMilliseconds(125);
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _issuer.Seed, start, start.AddMilliseconds(500)));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _issuer.Seed, start, start.AddSeconds(902)));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _other.Seed, start, start.AddMinutes(10)));
    }

    [Fact]
    public void WrongIssuerHolderVocabularyOrTypeNeverReleasesClaims()
    {
        string jwt = Issue();
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var otherIssuer));
        Assert.Equal(JsonValueKind.Undefined, otherIssuer.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            "AdminCredential", Vocabulary, Now, out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, new Uri("https://other.example/v1"), Now, out _));
    }

    [Fact]
    public void TamperingOldPrivateContextAndDirectVc2AreRejected()
    {
        string jwt = Issue();
        var parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(jwt)
            .Replace("active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts), _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));

        string oldProfile = SignPayload(new
        {
            iss = _issuer.Did, sub = _holder.Did,
            iat = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            nbf = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            exp = Now.AddMinutes(10).ToUnixTimeSeconds(),
            vc = new
            {
                context = new[] { "https://www.w3.org/2018/credentials/v1", Vocabulary.AbsoluteUri },
                type = new[] { "VerifiableCredential", CredentialType },
                credentialSubject = new { id = _holder.Did, membership = "active" }
            }
        });
        Assert.False(JwtVcJsonCredential.TryVerify(oldProfile, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));

        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string direct = Vcdm20JoseCredential.Create(_issuer.Did, _holder.Did, CredentialType,
            Vocabulary, subject.RootElement, _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
        Assert.False(JwtVcJsonCredential.TryVerify(direct, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void ExpiredAndPrematureCredentialsFailClosed()
    {
        string jwt = Issue();
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMinutes(11), out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMinutes(-2), out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void MismatchedIssuerPrivateKeyAndSubjectAreRejectedAtIssuance()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, subject.RootElement,
            _other.Seed, Now.AddMinutes(-1), Now.AddMinutes(10)));
        using var alienSubject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _other.Did, membership = "active" }));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, alienSubject.RootElement,
            _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10)));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, subject.RootElement,
            _issuer.Seed, Now, Now.AddHours(1)));
    }


    [Fact]
    public void IndependentJwtVc11IssuerCanOmitIatAndIncludeCredentialJti()
    {
        // W3C VC 1.1 maps credential id into JWT jti. The OpenID4VP 1.0
        // jwt_vc_json example contains jti and nbf but no iat. Construct the
        // JWS independently of HeroSSID's credential issuance/JWT signer.
        string jwt = SignExternalJwt(null, "https://issuer.example/credentials/external-123");
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var foreignSubject));
        Assert.Equal(JsonValueKind.Undefined, foreignSubject.ValueKind);
    }

    [Fact]
    public void IndependentlySignedW3cVc11JwtWithRegisteredJwtTypeVerifies()
    {
        // W3C VC Data Model 1.1 REC section 6.3.1: typ, if present, MUST
        // be JWT. The later vc+jwt format is a different media-type profile.
        // Sign independently with NSec, not HeroSSID's issuer/JWT signer.
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/rec-11-jwt-header", "JWT");

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var verified));
        Assert.Equal(_holder.Did, verified.GetProperty("id").GetString());
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var wrongIssuer));
        Assert.Equal(JsonValueKind.Undefined, wrongIssuer.ValueKind);
        string mismatchedHeaderType = SignExternalJwt(null,
            "https://issuer.example/credentials/rec-11-unknown-header", "vp+jwt");
        Assert.False(JwtVcJsonCredential.TryVerify(mismatchedHeaderType, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out var wrongType));
        Assert.Equal(JsonValueKind.Undefined, wrongType.ValueKind);
    }

    [Fact]
    public void IndependentIssuerCanSignBeforeItsCredentialBecomesValid()
    {
        // iat is signature issuance, whereas nbf is credential validity.
        // Both are authentically signed but need not share a timestamp.
        string jwt = SignExternalJwt(Now.AddMinutes(-2).ToUnixTimeSeconds(),
            "https://issuer.example/credentials/scheduled-123");
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject));
        Assert.Equal(_holder.Did, subject.GetProperty("id").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now.AddMinutes(-2), out _));
    }

    [Fact]
    public void IndependentJwtCredentialIdAndSignatureAreNotImplicitTrust()
    {
        string invalidId = SignExternalJwt(null, "javascript:alert(1)");
        Assert.False(JwtVcJsonCredential.TryVerify(invalidId, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var invalidClaims));
        Assert.Equal(JsonValueKind.Undefined, invalidClaims.ValueKind);

        string futureSigned = SignExternalJwt(Now.AddMinutes(1).ToUnixTimeSeconds(),
            "https://issuer.example/credentials/future-signing");
        Assert.False(JwtVcJsonCredential.TryVerify(futureSigned, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));

        string valid = SignExternalJwt(null, "https://issuer.example/credentials/external-123");
        string[] parts = valid.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(parts[1]).Replace(
                "active", "administrator", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts), _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));
    }


    [Fact]
    public void IndependentNormativeJwtCanBeRevokedWithoutLosingIssuerProvenance()
    {
        // NSec signs a VC1.1 JWT with no iat and an HTTPS jti, independently
        // of HeroSSID's issuer. The issuer's private status export must accept
        // it without relaxing the exact issuer signature or bounded JWT rules.
        string external = SignExternalJwt(null,
            "https://issuer.example/credentials/externally-issued", "JWT");
        var clock = new FixedClock(Now);
        string revoked = JwtVcJsonRevocationSnapshot.Create(_issuer.Did,
            [external], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, external, _issuer.Did, Now));
        string clean = JwtVcJsonRevocationSnapshot.Create(_issuer.Did,
            [], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(clean, external, _issuer.Did, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(clean, external, _other.Did, Now));

        string[] parts = external.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(parts[1]).Replace(
                "active", "admin", StringComparison.Ordinal));
        string tampered = string.Join('.', parts);
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(clean, tampered, _issuer.Did, Now));
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did,
                [tampered], _issuer.Seed, Now, clock));

        string wrongHeader = SignExternalJwt(null,
            "https://issuer.example/credentials/wrong-typ", "vp+jwt");
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did,
                [wrongHeader], _issuer.Seed, Now, clock));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(clean, wrongHeader, _issuer.Did, Now));
    }

    [Fact]
    public void HistoricalPrivateJwtTypeRemainsRevocable()
    {
        string legacy = SignExternalJwt(null,
            "https://issuer.example/credentials/legacy-header", "vc+jwt");
        var clock = new FixedClock(Now);
        string snapshot = JwtVcJsonRevocationSnapshot.Create(_issuer.Did,
            [legacy], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(snapshot, legacy, _issuer.Did, Now));
    }

    [Fact]
    public void IndependentVc11JwtWithoutOptionalKidRequiresPinnedIssuerAndAuthenticSignature()
    {
        // VC Data Model 1.1 REC §6.3.1 allows omitting kid. For did:key
        // verification, the trust anchor MUST remain the verifier-pinned DID.
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/no-kid", "JWT", includeKid: false);
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);

        string[] segments = jwt.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(segments[1]).Replace(
                "active", "administrator", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', segments),
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));

        // Omission is an opt-in normative JWT-only profile, not a way to
        // bypass the legacy issuer kid or accept a mismatched explicit kid.
        string legacyWithoutKid = SignExternalJwt(null,
            "https://issuer.example/credentials/legacy-no-kid", "vc+jwt", includeKid: false);
        Assert.False(JwtVcJsonCredential.TryVerify(legacyWithoutKid,
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
        string wrongKid = SignExternalJwt(null,
            "https://issuer.example/credentials/wrong-kid", "JWT",
            headerKidOverride: _other.Did + "#" + _other.Did["did:key:".Length..]);
        Assert.False(JwtVcJsonCredential.TryVerify(wrongKid,
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void IssuerPrivateStatusAcceptsAuthenticNormativeJwtWithoutOptionalKid()
    {
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/status-no-kid", "JWT", includeKid: false);
        var clock = new FixedClock(Now);
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, [jwt], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
        string clean = JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(clean, jwt, _issuer.Did, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(clean, jwt, _other.Did, Now));
    }

    [Fact]
    public void IndependentVc11JwtCanRepresentHolderIdOnlyInSignedSubClaim()
    {
        // VC Data Model 1.1 REC 6.3.1 maps credentialSubject.id to sub.
        // A standards-shaped external issuer need not duplicate this field in vc.
        // The holder DID still comes from an independently pinned expectation,
        // not an arbitrary unverified claim in the incoming JWT.
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/sub-only", "JWT",
            includeKid: false, omitSubjectId: true);

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out JsonElement claims));
        Assert.False(claims.TryGetProperty("id", out _));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out JsonElement foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);

        string[] segments = jwt.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(segments[1]).Replace(
                "active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', segments),
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Fact]
    public void IndependentVc11JwtWithSubOnlyCanBeRevokedUsingOriginalIssuerSignature()
    {
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/sub-only-revoked", "JWT",
            includeKid: false, omitSubjectId: true);
        var clock = new FixedClock(Now);
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, [jwt], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
        string clean = JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, [], _issuer.Seed, Now, clock);
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(clean, jwt, _issuer.Did, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(clean, jwt, _other.Did, Now));
    }

    [Fact]
    public void ConflictingExplicitSubjectIdCannotBeReplacedByJwtSub()
    {
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/sub-conflict", "JWT",
            omitSubjectId: false, subjectIdOverride: _other.Did);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var claims));
        Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
                _issuer.Seed, Now, new FixedClock(Now)));
    }

    [Fact]
    public void LegacyVcJwtCannotOmitSubjectIdOrBypassPinnedHolder()
    {
        // The sub-only VC1.1 mapping is intentionally limited to typ=JWT.
        string legacy = SignExternalJwt(null,
            "https://issuer.example/credentials/legacy-sub-only", "vc+jwt",
            omitSubjectId: true);
        Assert.False(JwtVcJsonCredential.TryVerify(legacy, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [legacy],
                _issuer.Seed, Now, new FixedClock(Now)));

        // Even a correctly signed normative JWT cannot hide a present
        // but empty nested identifier behind its valid signed sub.
        string emptyId = SignExternalJwt(null,
            "https://issuer.example/credentials/empty-sub-id", "JWT",
            subjectIdOverride: string.Empty);
        Assert.False(JwtVcJsonCredential.TryVerify(emptyId, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [emptyId],
                _issuer.Seed, Now, new FixedClock(Now)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IssuerCanSignVc11SubOnlyCredentialWithoutFabricatingNestedId(bool includeJti)
    {
        // VC Data Model 1.1 §6.3.1 maps credentialSubject.id to JWT sub.
        // The issuer should be able to serialize that exact representation;
        // the verifier must still independently pin the expected holder.
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { membership = "active" }));
        var credentialId = new Uri("https://issuer.example/credentials/sub-only-issuer");
        string jwt = includeJti
            ? JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType,
                Vocabulary, subject.RootElement, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(10), credentialId)
            : JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType,
                Vocabulary, subject.RootElement, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(10));

        using var signed = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal(_holder.Did, signed.RootElement.GetProperty("sub").GetString());
        Assert.False(signed.RootElement.GetProperty("vc")
            .GetProperty("credentialSubject").TryGetProperty("id", out _));
        Assert.Equal(includeJti, signed.RootElement.TryGetProperty("jti", out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var verified, out string? identifier));
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.False(verified.TryGetProperty("id", out _));
        Assert.Equal(includeJti ? credentialId.AbsoluteUri : null, identifier);

        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out var wrongHolder));
        Assert.Equal(JsonValueKind.Undefined, wrongHolder.ValueKind);
        string revoked = JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
            _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
    }

    [Fact]
    public void IssuerCanSignPortableCredentialIdWithOriginalCredentialAndStatusSignature()
    {
        var id = new Uri("https://issuer.example/credentials/membership-123");
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        string jwt = JwtVcJsonCredential.Create(_issuer.Did, _holder.Did,
            CredentialType, Vocabulary, subject.RootElement, _issuer.Seed,
            Now.AddMinutes(-1), Now.AddMinutes(10), id);

        using var signed = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal(id.AbsoluteUri, signed.RootElement.GetProperty("jti").GetString());
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var verified, out string? verifiedId));
        Assert.Equal(id.AbsoluteUri, verifiedId);
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        string status = JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
            _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(status, jwt, _issuer.Did, Now));
    }

    [Fact]
    public void IndependentSignedJtiIsReturnedOnlyAfterIssuerHolderAndSignatureValidation()
    {
        const string expectedId = "https://issuer.example/credentials/independent-id";
        string jwt = SignExternalJwt(null, expectedId, "JWT", includeKid: false);
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject, out string? identifier));
        Assert.Equal(expectedId, identifier);
        Assert.Equal("active", subject.GetProperty("membership").GetString());

        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out var foreign, out string? foreignId));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.Null(foreignId);

        string[] parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(parts[1]).Replace(
                "independent-id", "changed-id", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', parts),
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            Now, out var tampered, out string? tamperedId));
        Assert.Equal(JsonValueKind.Undefined, tampered.ValueKind);
        Assert.Null(tamperedId);

        string withoutId = Issue();
        Assert.True(JwtVcJsonCredential.TryVerify(withoutId,
            _issuer.Did, _holder.Did, CredentialType, Vocabulary,
            Now, out _, out string? absentId));
        Assert.Null(absentId);
    }

    [Fact]
    public void CredentialIdIssuanceRejectsUntrustedOrUnsupportedIdentifiers()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        foreach (string rejected in new[]
        {
            "http://issuer.example/credentials/123",
            "https://user:pass@issuer.example/credentials/123",
            "https://issuer.example/credentials/" + new string('x', 2048)
        })
        {
            Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.Create(
                _issuer.Did, _holder.Did, CredentialType, Vocabulary,
                subject.RootElement, _issuer.Seed,
                Now.AddMinutes(-1), Now.AddMinutes(10), new Uri(rejected)));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IndependentlySignedVc11WithoutOptionalTypPreservesIssuerHolderAndRevocation(bool includeKid)
    {
        // VC Data Model 1.1 REC 6.3.1: JOSE typ, if present, MUST equal JWT.
        // A different Ed25519 signer constructs the header with no typ at all.
        // Its omission must not bypass the pinned issuer/holder or legacy rules.
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/typ-omitted", "JWT",
            includeKid: includeKid, omitSubjectId: true, omitTyp: true);
        using var header = JsonDocument.Parse(Ed25519JwtSigner.ExtractHeader(jwt));
        Assert.False(header.RootElement.TryGetProperty("typ", out _));
        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var subject));
        Assert.Equal("active", subject.GetProperty("membership").GetString());
        Assert.False(subject.TryGetProperty("id", out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out _));

        // Omitting typ must not cause an explicitly wrong kid to be ignored,
        // including by the separate issuer-status ingestion path.
        string wrongKid = SignExternalJwt(null,
            "https://issuer.example/credentials/typ-omitted-wrong-kid",
            "JWT", includeKid: true,
            headerKidOverride: _other.Did + "#" + _other.Did["did:key:".Length..],
            omitSubjectId: true, omitTyp: true);
        Assert.False(JwtVcJsonCredential.TryVerify(wrongKid, _issuer.Did,
            _holder.Did, CredentialType, Vocabulary, Now, out _));
        Assert.Throws<CryptographicException>(() =>
            JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [wrongKid],
                _issuer.Seed, Now, new FixedClock(Now)));

        string revoked = JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
            _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));

        string[] segments = jwt.Split('.');
        segments[1] = Base64UrlEncoder.Encode(
            Base64UrlEncoder.DecodeString(segments[1]).Replace(
                "active", "admin", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerify(string.Join('.', segments),
            _issuer.Did, _holder.Did, CredentialType, Vocabulary, Now, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentlySignedVc11SingleElementSubjectArrayKeepsIssuerAndHolderBinding(bool omitSubjectId)
    {
        // A real independent Ed25519 issuer signs VC1.1's valid array form.
        // The bounded verifier must disclose only the single authenticated object.
        object subject = omitSubjectId
            ? new { membership = "active" }
            : new { id = _holder.Did, membership = "active" };
        string jwt = SignExternalJwt(null,
            "https://issuer.example/credentials/array-single", "JWT",
            includeKid: false, credentialSubjectOverride: new[] { subject });

        Assert.True(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var verified));
        Assert.Equal(JsonValueKind.Object, verified.ValueKind);
        Assert.Equal("active", verified.GetProperty("membership").GetString());
        Assert.Equal(!omitSubjectId, verified.TryGetProperty("id", out _));
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _other.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out var foreign));
        Assert.Equal(JsonValueKind.Undefined, foreign.ValueKind);
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _other.Did,
            CredentialType, Vocabulary, Now, out _));

        // Status still hashes the exact original issuer-signed JWT.
        string revoked = JwtVcJsonRevocationSnapshot.Create(
            _issuer.Did, [jwt], _issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(revoked, jwt, _issuer.Did, Now));
    }

    [Fact]
    public void SubjectArrayRejectsMultipleOrConflictingHolderClaimsAndLegacyDowngrade()
    {
        object valid = new { id = _holder.Did, membership = "active" };
        object other = new { id = _other.Did, membership = "admin" };
        object[] invalidSubjects =
        [
            Array.Empty<object>(),
            new[] { valid, other },
            new[] { other },
            new object[] { new { id = "", membership = "active" } },
            new object[] { new { id = _holder.Did, membership = "active",
                nested = new Dictionary<string, object> { ["@context"] = "https://evil.example/context" } } }
        ];

        foreach (object subject in invalidSubjects)
        {
            string jwt = SignExternalJwt(null,
                "https://issuer.example/credentials/array-rejected", "JWT",
                includeKid: false, credentialSubjectOverride: subject);
            Assert.False(JwtVcJsonCredential.TryVerify(jwt, _issuer.Did, _holder.Did,
                CredentialType, Vocabulary, Now, out var claims));
            Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
            Assert.Throws<CryptographicException>(() =>
                JwtVcJsonRevocationSnapshot.Create(_issuer.Did, [jwt],
                    _issuer.Seed, Now, new FixedClock(Now)));
        }

        string legacy = SignExternalJwt(null,
            "https://issuer.example/credentials/array-legacy", "vc+jwt",
            credentialSubjectOverride: new[] { valid });
        Assert.False(JwtVcJsonCredential.TryVerify(legacy, _issuer.Did, _holder.Did,
            CredentialType, Vocabulary, Now, out _));
    }

    private string SignExternalJwt(long? signatureIssuedAt, string credentialId,
        string tokenType = "vc+jwt", bool includeKid = true, string? headerKidOverride = null,
        bool omitSubjectId = false, string? subjectIdOverride = null, bool omitTyp = false,
        object? credentialSubjectOverride = null)
    {
        string kid = _issuer.Did + "#" + _issuer.Did["did:key:".Length..];
        string header = omitTyp
            ? includeKid
                ? Base64UrlEncoder.Encode(JsonSerializer.Serialize(
                    new { alg = "EdDSA", kid = headerKidOverride ?? kid }))
                : Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "EdDSA" }))
            : includeKid
                ? Base64UrlEncoder.Encode(JsonSerializer.Serialize(
                    new { alg = "EdDSA", typ = tokenType, kid = headerKidOverride ?? kid }))
                : Base64UrlEncoder.Encode(JsonSerializer.Serialize(
                    new { alg = "EdDSA", typ = tokenType }));
        var claims = new Dictionary<string, object>
        {
            ["iss"] = _issuer.Did,
            ["sub"] = _holder.Did,
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = credentialId,
            ["vc"] = new Dictionary<string, object>
            {
                ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1",
                    Vocabulary.AbsoluteUri },
                ["type"] = new[] { "VerifiableCredential", CredentialType },
                ["credentialSubject"] = credentialSubjectOverride ?? (omitSubjectId
                    ? (object)new { membership = "active" }
                    : new { id = subjectIdOverride ?? _holder.Did, membership = "active" })
            }
        };
        if (signatureIssuedAt is long issued)
        {
            claims["iat"] = issued;
        }

        string payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(claims));
        string signingInput = header + "." + payload;
        using var signer = Key.Import(SignatureAlgorithm.Ed25519, _issuer.Seed,
            KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(
            signer, Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private string Issue()
    {
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = _holder.Did, membership = "active" }));
        return JwtVcJsonCredential.Create(_issuer.Did, _holder.Did, CredentialType, Vocabulary,
            subject.RootElement, _issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(10));
    }

    private string SignPayload<T>(T payload)
    {
        string kid = _issuer.Did + "#" + _issuer.Did["did:key:".Length..];
        return Ed25519JwtSigner.CreateSignedJwt(JsonSerializer.Serialize(
            new { alg = "EdDSA", typ = "vc+jwt", kid }),
            JsonSerializer.Serialize(payload), _issuer.Seed);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        publicKey.CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
