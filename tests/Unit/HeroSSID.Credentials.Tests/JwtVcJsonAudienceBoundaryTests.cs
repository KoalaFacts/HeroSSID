using System.Reflection;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// RFC 7519 audience routing is an issuer assertion, not proof of the
/// relying party's identity, holder possession, user consent or authorization.
/// </summary>
public sealed class JwtVcJsonAudienceBoundaryTests
{
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri Recipient = new("https://verifier.example/credential-intake");
    private static readonly Uri OtherRecipient = new("https://other-verifier.example/credential-intake");
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 1, 0, 0, TimeSpan.Zero);
    private const string CredentialType = "MembershipCredential";

    [Fact]
    public void IssuerAudienceBoundCredentialRequiresIndependentRecipientPin()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        var outsider = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));

        // Reflection is deliberate: the test-only RED must compile on the
        // unchanged SDK and fail at xUnit runtime if the public API is missing.
        MethodInfo? issue = typeof(JwtVcJsonCredential).GetMethod(
            "CreateForAudience", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(issue);
        string jwt = Assert.IsType<string>(issue.Invoke(null,
            [issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
                issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5), Recipient]));

        using var document = JsonDocument.Parse(Ed25519JwtSigner.ExtractPayload(jwt));
        Assert.Equal(Recipient.AbsoluteUri,
            document.RootElement.GetProperty("aud").GetString());

        Assert.True(Verify(jwt, issuer.Did, holder.Did, Recipient, out var verified));
        Assert.Equal("active", verified.GetProperty("membership").GetString());

        Assert.False(Verify(jwt, issuer.Did, holder.Did, OtherRecipient, out var wrongAudience));
        Assert.Equal(JsonValueKind.Undefined, wrongAudience.ValueKind);
        Assert.False(Verify(jwt, outsider.Did, holder.Did, Recipient, out var wrongIssuer));
        Assert.Equal(JsonValueKind.Undefined, wrongIssuer.ValueKind);
        Assert.False(Verify(jwt, issuer.Did, outsider.Did, Recipient, out var wrongHolder));
        Assert.Equal(JsonValueKind.Undefined, wrongHolder.ValueKind);
        Assert.False(Verify(jwt, issuer.Did, holder.Did, Recipient, out var expired, Now.AddMinutes(6)));
        Assert.Equal(JsonValueKind.Undefined, expired.ValueKind);

        // The old no-audience API must NOT silently start accepting aud tokens.
        Assert.False(JwtVcJsonCredential.TryVerify(jwt, issuer.Did, holder.Did,
            CredentialType, Context, Now, out var unbound));
        Assert.Equal(JsonValueKind.Undefined, unbound.ValueKind);
        string[] parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(
            Ed25519JwtSigner.ExtractPayload(jwt).Replace(
                "active", "administrator", StringComparison.Ordinal));
        Assert.False(Verify(string.Join('.', parts), issuer.Did, holder.Did, Recipient,
            out var altered));
        Assert.Equal(JsonValueKind.Undefined, altered.ValueKind);
    }

    [Fact]
    public void IndependentlySignedRfc7519StringOrArrayAudienceIsVerifiedAgainstPinnedRecipient()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();

        string single = SignExternal(issuer, holder.Did, Recipient.AbsoluteUri);
        Assert.True(Verify(single, issuer.Did, holder.Did, Recipient, out _));
        Assert.False(Verify(single, issuer.Did, holder.Did, OtherRecipient, out _));

        // This is an independent NSec signing path, not CreateForAudience's
        // in-repository issuer serializer reused as an interoperability claim.
        string array = SignExternal(issuer, holder.Did,
            new[] { OtherRecipient.AbsoluteUri, Recipient.AbsoluteUri });
        Assert.True(Verify(array, issuer.Did, holder.Did, Recipient, out var claims));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.True(Verify(array, issuer.Did, holder.Did, OtherRecipient, out _));
        Assert.False(Verify(array, issuer.Did, holder.Did,
            new Uri("https://stranger.example/rp"), out var notIntended));
        Assert.Equal(JsonValueKind.Undefined, notIntended.ValueKind);
    }

    [Fact]
    public void MalformedAudienceAndMissingAudienceFailWithoutClaimDisclosure()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        object?[] rejected =
        [
            null,
            "",
            123,
            Array.Empty<string>(),
            new[] { Recipient.AbsoluteUri, Recipient.AbsoluteUri },
            new[] { Recipient.AbsoluteUri, "http://insecure.example/rp" },
            new[] { Recipient.AbsoluteUri, "https://evil@example.org/rp" },
            new[] { Recipient.AbsoluteUri, "https://another.example/rp#fragment" },
            new[] { Recipient.AbsoluteUri, "https://different.example/" ,
                "https://third.example/", "https://fourth.example/",
                "https://fifth.example/", "https://sixth.example/",
                "https://seventh.example/", "https://eighth.example/",
                "https://ninth.example/" }
        ];
        foreach (object? audience in rejected)
        {
            string jwt = SignExternal(issuer, holder.Did, audience, includeAudience: audience is not null);
            Assert.False(Verify(jwt, issuer.Did, holder.Did, Recipient,
                out JsonElement claims), $"Unexpected audience: {audience}");
            Assert.Equal(JsonValueKind.Undefined, claims.ValueKind);
        }

        Assert.Throws<ArgumentException>(() => IssueWithAudience(issuer, holder, 
            new Uri("http://verifier.example/rp")));
        Assert.Throws<ArgumentException>(() => IssueWithAudience(issuer, holder,
            new Uri("https://user@verifier.example/rp")));
        Assert.Throws<ArgumentException>(() => IssueWithAudience(issuer, holder,
            new Uri("https://verifier.example/rp#fragment")));
    }

    [Fact]
    public void IssuerCanRevokeTheExactOriginalAudienceBoundJwtWithoutOverridingRecipientPin()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        string revokedJwt = IssueWithAudience(issuer, holder, Recipient);
        string unlistedJwt = IssueWithAudience(issuer, holder, OtherRecipient);

        // The private issuer-signed export authenticates the original token
        // and its digest; it does not decide which audience may use the VC.
        string snapshot = JwtVcJsonRevocationSnapshot.Create(issuer.Did,
            [revokedJwt], issuer.Seed, Now, new FixedClock(Now));
        Assert.Equal(RevocationSnapshotCheckResult.Revoked,
            JwtVcJsonRevocationSnapshot.Check(snapshot, revokedJwt,
                issuer.Did, Now));
        Assert.Equal(RevocationSnapshotCheckResult.NotListed,
            JwtVcJsonRevocationSnapshot.Check(snapshot, unlistedJwt,
                issuer.Did, Now));
        Assert.Equal(RevocationSnapshotCheckResult.Invalid,
            JwtVcJsonRevocationSnapshot.Check(snapshot, revokedJwt,
                NewIdentity().Did, Now));

        // Issuer non-listing is not a permission to ignore recipient policy.
        Assert.False(Verify(unlistedJwt, issuer.Did, holder.Did,
            Recipient, out var wrongRecipient));
        Assert.Equal(JsonValueKind.Undefined, wrongRecipient.ValueKind);
    }

    [Fact]
    public void IssuerCanBindMetadataAndFractionalValidityToOneRecipientScopedJwt()
    {
        var issuer = NewIdentity();
        var holder = NewIdentity();
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(
            new { id = holder.Did, membership = "active" }));
        var id = new Uri("https://issuer.example/credentials/recipient-metadata-01");
        const string displayName = "Organisation display only";
        DateTimeOffset from = Now.AddMinutes(-1).AddTicks(17);
        DateTimeOffset until = Now.AddMinutes(5).AddTicks(29);

        string jwt = JwtVcJsonCredential.CreateForAudienceWithMetadata(
            issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
            issuer.Seed, from, until, Recipient, id, displayName, exactValidity: true);
        Assert.True(JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
            jwt, issuer.Did, holder.Did, CredentialType, Context, Recipient,
            Now, out var claims, out var signedId, out var signedName,
            out var signedFrom, out var signedUntil));
        Assert.Equal("active", claims.GetProperty("membership").GetString());
        Assert.Equal(id.AbsoluteUri, signedId);
        Assert.Equal(displayName, signedName);
        Assert.Equal(from, signedFrom);
        Assert.Equal(until, signedUntil);

        Assert.False(JwtVcJsonCredential.TryVerifyForAudienceWithValidity(
            jwt, issuer.Did, holder.Did, CredentialType, Context, OtherRecipient,
            Now, out var wrongSubject, out var wrongId, out var wrongName,
            out var wrongStart, out var wrongEnd));
        Assert.Equal(JsonValueKind.Undefined, wrongSubject.ValueKind);
        Assert.Null(wrongId);
        Assert.Null(wrongName);
        Assert.Null(wrongStart);
        Assert.Null(wrongEnd);

        string[] parts = jwt.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Ed25519JwtSigner.ExtractPayload(jwt)
            .Replace(displayName, "Forged organisation name", StringComparison.Ordinal));
        Assert.False(JwtVcJsonCredential.TryVerifyForAudience(
            string.Join('.', parts), issuer.Did, holder.Did, CredentialType,
            Context, Recipient, Now, out _));
        Assert.Throws<ArgumentException>(() => JwtVcJsonCredential.CreateForAudienceWithMetadata(
            issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
            issuer.Seed, from, until, Recipient, id, "Untrusted\nName",
            exactValidity: true));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static string IssueWithAudience(
        (byte[] Seed, string Did) issuer, (byte[] Seed, string Did) holder, Uri recipient)
    {
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "CreateForAudience", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        using var subject = JsonDocument.Parse(JsonSerializer.Serialize(new { id = holder.Did }));
        try
        {
            return Assert.IsType<string>(method.Invoke(null,
                [issuer.Did, holder.Did, CredentialType, Context, subject.RootElement,
                    issuer.Seed, Now.AddMinutes(-1), Now.AddMinutes(5), recipient]));
        }
        catch (TargetInvocationException ex) when (ex.InnerException is ArgumentException)
        {
            throw ex.InnerException;
        }
    }

    private static bool Verify(string jwt, string issuerDid, string holderDid,
        Uri expectedRecipient, out JsonElement claims, DateTimeOffset? now = null)
    {
        MethodInfo? method = typeof(JwtVcJsonCredential).GetMethod(
            "TryVerifyForAudience", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        object?[] args =
        [
            jwt, issuerDid, holderDid, CredentialType, Context, expectedRecipient,
            now ?? Now, default(JsonElement)
        ];
        bool verified = Assert.IsType<bool>(method.Invoke(null, args));
        claims = Assert.IsType<JsonElement>(args[7]);
        return verified;
    }

    private static string SignExternal(
        (byte[] Seed, string Did) issuer, string holderDid, object? audience,
        bool includeAudience = true)
    {
        string kid = issuer.Did + "#" + issuer.Did["did:key:".Length..];
        string header = JsonSerializer.Serialize(new { alg = "EdDSA", typ = "JWT", kid });
        var body = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = issuer.Did,
            ["sub"] = holderDid,
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["vc"] = new Dictionary<string, object>
            {
                ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1", Context.AbsoluteUri },
                ["type"] = new[] { "VerifiableCredential", CredentialType },
                ["credentialSubject"] = new { id = holderDid, membership = "active" }
            }
        };
        if (includeAudience)
        {
            body["aud"] = audience;
        }

        string input = Base64UrlEncoder.Encode(header) + "." +
            Base64UrlEncoder.Encode(JsonSerializer.Serialize(body));
        using var key = Key.Import(SignatureAlgorithm.Ed25519, issuer.Seed,
            KeyBlobFormat.RawPrivateKey);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(
            key, Encoding.ASCII.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }

    private static (byte[] Seed, string Did) NewIdentity()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(prefixed, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey),
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(prefixed));
    }
}
