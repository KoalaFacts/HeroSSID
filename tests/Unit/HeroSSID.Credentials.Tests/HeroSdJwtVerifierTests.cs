using HeroSSID.Credentials.Implementations;
using HeroSSID.Credentials.SdJwt;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Integration tests for HeroSdJwtVerifier using real HeroSD-JWT NuGet package v1.1.3
/// Tests the production implementation against the ISdJwtVerifier interface
/// </summary>
public sealed class HeroSdJwtVerifierTests
{
    private readonly HeroSdJwtGenerator _generator;
    private readonly HeroSdJwtVerifier _verifier;
    private readonly byte[] _testHmacKey;

    public HeroSdJwtVerifierTests()
    {
        _generator = new HeroSdJwtGenerator();
        _verifier = new HeroSdJwtVerifier();
        // Generate a 256-bit HMAC key for HS256
        _testHmacKey = Encoding.UTF8.GetBytes("test-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256");
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
            _testHmacKey,
            issuerDid,
            holderDid);

        // Act - Verify the SD-JWT
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testHmacKey);

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
            _testHmacKey,
            issuerDid,
            holderDid);

        // Act
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testHmacKey);

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
            _testHmacKey,
            issuerDid,
            holderDid);

        // Use different key for verification
        var wrongKey = Encoding.UTF8.GetBytes("wrong-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256-test");

        // Act - Verify with wrong key
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            wrongKey);

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
            _testHmacKey);

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
            _verifier.VerifySdJwt(emptySdJwt, disclosures, _testHmacKey));
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
            _testHmacKey,
            issuerDid,
            holderDid);

        // Act - Verify
        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testHmacKey);

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
            _testHmacKey,
            issuerDid,
            holderDid);

        var verificationResult = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testHmacKey);

        // Assert
        Assert.True(verificationResult.IsValid);
        Assert.Equal(SdJwtVerificationStatus.Valid, verificationResult.Status);
        Assert.Empty(verificationResult.ValidationErrors);
    }
}
