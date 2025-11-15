using HeroSSID.Credentials.Implementations;
using HeroSSID.Credentials.SdJwt;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Integration tests for HeroSdJwtVerifier using real HeroSD-JWT NuGet package v1.1.3
/// Tests the production implementation against the ISdJwtVerifier interface with Ed25519 verification
/// </summary>
public sealed class HeroSdJwtVerifierTests
{
    private readonly HeroSdJwtGenerator _generator;
    private readonly HeroSdJwtVerifier _verifier;
    private readonly byte[] _testEd25519PrivateKey;
    private readonly byte[] _testEd25519PublicKey;

    public HeroSdJwtVerifierTests()
    {
        _generator = new HeroSdJwtGenerator();
        _verifier = new HeroSdJwtVerifier();

        // Generate Ed25519 key pair for testing
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(algorithm, keyParams);

        _testEd25519PrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        _testEd25519PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    [Fact]
    public void VerifySdJwt_WithValidSdJwt_ReturnsValidResult()
    {
        // Arrange - Generate a valid SD-JWT
        var claims = new Dictionary<string, object>
        {
            { "name", "Alice" },
            { "email", "alice@example.com" },
            { "age", 30 }
        };
        var selectiveDisclosureClaims = new[] { "email", "age" };
        var issuerDid = "did:key:z6MkIssuer123";
        var holderDid = "did:key:z6MkHolder456";

        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Act - Verify the SD-JWT
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testEd25519PublicKey);

        // Assert
        Assert.NotNull(verificationResult);
        Assert.True(verificationResult.IsValid);
        Assert.Equal(SdJwtVerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);
    }

    [Fact]
    public void VerifySdJwt_WithValidSdJwt_ReconstructsDisclosedClaims()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Bob" },
            { "email", "bob@example.com" },
            { "role", "developer" }
        };
        var selectiveDisclosureClaims = new[] { "email" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Act
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testEd25519PublicKey);

        // Assert
        Assert.NotNull(verificationResult.DisclosedClaims);

        // Should contain issuer and holder DIDs
        Assert.Equal(issuerDid, verificationResult.IssuerDid);
        Assert.Equal(holderDid, verificationResult.HolderDid);
    }

    [Fact]
    public void VerifySdJwt_WithInvalidSignature_ReturnsInvalidResult()
    {
        // Arrange - Generate SD-JWT with one key
        var claims = new Dictionary<string, object> { { "name", "Alice" } };
        var selectiveDisclosureClaims = new[] { "name" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Generate different Ed25519 key pair for verification (wrong key)
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var wrongKey = Key.Create(algorithm, keyParams);
        var wrongPublicKey = wrongKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        // Act - Verify with wrong key
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            wrongPublicKey);

        // Assert
        Assert.False(verificationResult.IsValid);
        Assert.NotEqual(SdJwtVerificationStatus.Valid, verificationResult.Status);
        Assert.NotEmpty(verificationResult.ValidationErrors);
    }

    [Fact]
    public void VerifySdJwt_WithMalformedSdJwt_ReturnsMalformedStatus()
    {
        // Arrange
        var malformedSdJwt = "not.a.valid.sd-jwt";
        var disclosures = Array.Empty<string>();

        // Act
        var verificationResult = _verifier.VerifySdJwt(
            malformedSdJwt,
            disclosures,
            _testEd25519PublicKey);

        // Assert
        Assert.False(verificationResult.IsValid);
        Assert.NotEmpty(verificationResult.ValidationErrors);
    }

    [Fact]
    public void VerifySdJwt_WithEmptySdJwt_ThrowsArgumentException()
    {
        // Arrange
        var emptySdJwt = string.Empty;
        var disclosures = Array.Empty<string>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _verifier.VerifySdJwt(emptySdJwt, disclosures, _testEd25519PublicKey));
    }

    [Fact]
    public void VerifySdJwt_WithNullDisclosures_ThrowsArgumentNullException()
    {
        // Arrange
        var compactSdJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature~";
        string[]? disclosures = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _verifier.VerifySdJwt(compactSdJwt, disclosures!, _testHmacKey));
    }

    [Fact]
    public void VerifySdJwt_WithNullIssuerPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var compactSdJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature~";
        var disclosures = Array.Empty<string>();
        byte[]? issuerPublicKey = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _verifier.VerifySdJwt(compactSdJwt, disclosures, issuerPublicKey!));
    }

    [Fact]
    public void RoundTrip_GenerateAndVerify_PreservesStandardClaims()
    {
        // Arrange - Generate SD-JWT with both selective and regular claims
        var claims = new Dictionary<string, object>
        {
            { "name", "Alice" },  // Regular claim (always visible)
            { "email", "alice@example.com" },  // Selective claim
            { "role", "admin" }  // Regular claim
        };
        var selectiveDisclosureClaims = new[] { "email" };
        var issuerDid = "did:key:z6MkIssuerTest";
        var holderDid = "did:key:z6MkHolderTest";

        // Act - Generate
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Act - Verify
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testEd25519PublicKey);

        // Assert
        Assert.True(verificationResult.IsValid);
        Assert.NotNull(verificationResult.DisclosedClaims);

        // Verify standard JWT claims (iss, sub) are present
        Assert.True(verificationResult.DisclosedClaims.ContainsKey("iss"));
        Assert.True(verificationResult.DisclosedClaims.ContainsKey("sub"));

        // Verify DIDs match
        Assert.Equal(issuerDid, verificationResult.IssuerDid);
        Assert.Equal(holderDid, verificationResult.HolderDid);
    }

    [Fact]
    public void RoundTrip_MultipleSelectiveClaims_VerifiesSuccessfully()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Test User" },
            { "email", "test@example.com" },
            { "phone", "+1-555-1234" },
            { "address", "123 Test St" },
            { "age", 25 }
        };
        var selectiveDisclosureClaims = new[] { "email", "phone", "address", "age" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act - Generate and verify
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testEd25519PublicKey);

        // Assert
        Assert.True(verificationResult.IsValid);
        Assert.Equal(SdJwtVerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);
    }
}
