using HeroSSID.Credentials.Models;
using HeroSSID.Credentials.Services;
using System;
using System.Collections.Generic;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Unit tests for MockSdJwtVerifier
/// Verifies mock SD-JWT verification for MVP development
/// </summary>
public sealed class MockSdJwtVerifierTests
{
    private readonly MockSdJwtGenerator _generator;
    private readonly MockSdJwtVerifier _verifier;
    private readonly byte[] _testSigningKey;
    private readonly byte[] _testPublicKey;
    private static readonly string[] SingleNameClaim = ["name"];
    private static readonly string[] SingleDataClaim = ["data"];
    private static readonly string[] SingleTestClaim = ["test"];
    private static readonly string[] NameAndDegreeClaims = ["name", "degree"];
    private static readonly string[] NameAgeCityCountryClaims = ["name", "age", "city", "country"];
    private static readonly string[] SingleDisclosure = ["disclosure1"];

    public MockSdJwtVerifierTests()
    {
        _generator = new MockSdJwtGenerator();
        _verifier = new MockSdJwtVerifier();

        // Generate a real Ed25519 key pair for testing
        using var key = NSec.Cryptography.Key.Create(
            NSec.Cryptography.SignatureAlgorithm.Ed25519,
            new NSec.Cryptography.KeyCreationParameters { ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport });

        var rawPrivateKey = key.Export(NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        _testSigningKey = rawPrivateKey[..32]; // Extract seed (first 32 bytes)
        _testPublicKey = key.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);
    }

    [Fact]
    public void VerifySdJwtValidSdJwtReturnsValidResult()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Alice" },
            { "degree", "PhD" }
        };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            NameAndDegreeClaims,
            _testSigningKey,
            "did:hero:issuer",
            "did:hero:holder");

        // Act
        var result = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(SdJwtVerificationStatus.Valid, result.Status);
        Assert.Empty(result.ValidationErrors);
    }

    [Fact]
    public void VerifySdJwtValidResultContainsDisclosedClaims()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Bob" },
            { "email", "bob@example.com" }
        };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleNameClaim,
            _testSigningKey,
            "did:hero:issuer",
            "did:hero:holder");

        // Act
        var result = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.NotNull(result.DisclosedClaims);
        Assert.Contains("name", result.DisclosedClaims.Keys);
        Assert.Equal("Bob", result.DisclosedClaims["name"].ToString());
    }

    [Fact]
    public void VerifySdJwtValidResultContainsIssuerAndHolder()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "test", "value" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleTestClaim,
            _testSigningKey,
            "did:hero:issuer123",
            "did:hero:holder456");

        // Act
        var result = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal("did:hero:issuer123", result.IssuerDid);
        Assert.Equal("did:hero:holder456", result.HolderDid);
    }

    [Fact]
    public void VerifySdJwtMalformedJwtReturnsInvalid()
    {
        // Arrange
        var malformedJwt = "not.a.valid~jwt~format";
        var disclosures = SingleDisclosure;

        // Act
        var result = _verifier.VerifySdJwt(malformedJwt, disclosures, _testPublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(SdJwtVerificationStatus.SignatureInvalid, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
    }

    [Fact]
    public void VerifySdJwtEmptyJwtThrowsArgumentException()
    {
        // Arrange
        var emptyJwt = "";
        var disclosures = Array.Empty<string>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _verifier.VerifySdJwt(emptyJwt, disclosures, _testPublicKey));
    }

    [Fact]
    public void VerifySdJwtNullPublicKeyThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Charlie" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleNameClaim,
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _verifier.VerifySdJwt(sdJwtResult.CompactSdJwt, sdJwtResult.DisclosureTokens, null!));
    }

    [Fact]
    public void VerifySdJwtNullDisclosureTokensThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Diana" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleNameClaim,
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _verifier.VerifySdJwt(sdJwtResult.CompactSdJwt, null!, _testPublicKey));
    }

    [Fact]
    public void VerifySdJwtEmptyDisclosureTokensReturnsValid()
    {
        // Arrange - Generate SD-JWT with no selective claims
        var claims = new Dictionary<string, object> { { "public", "data" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            Array.Empty<string>(),
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Act
        var result = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            Array.Empty<string>(),
            _testPublicKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifySdJwtMultipleClaimsAllDisclosed()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Eve" },
            { "age", 30 },
            { "city", "Portland" },
            { "country", "USA" }
        };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            NameAgeCityCountryClaims,
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Act
        var result = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.NotNull(result.DisclosedClaims);
        Assert.Equal(4, result.DisclosedClaims.Count);
        Assert.Equal("Eve", result.DisclosedClaims["name"].ToString());
        Assert.Equal("30", result.DisclosedClaims["age"].ToString());
    }

    [Fact]
    public void VerifySdJwtConsistentResultsForSameInput()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "data", "test" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleDataClaim,
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Act - Verify twice
        var result1 = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);
        var result2 = _verifier.VerifySdJwt(
            sdJwtResult.CompactSdJwt,
            sdJwtResult.DisclosureTokens,
            _testPublicKey);

        // Assert - Results should be consistent
        Assert.Equal(result1.IsValid, result2.IsValid);
        Assert.Equal(result1.Status, result2.Status);
        Assert.Equal(result1.IssuerDid, result2.IssuerDid);
    }

    [Fact]
    public void VerifySdJwtTruncatedJwtReturnsInvalid()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Frank" } };
        var sdJwtResult = _generator.GenerateSdJwt(
            claims,
            SingleNameClaim,
            _testSigningKey,
            "did:hero:iss",
            "did:hero:sub");

        // Truncate the JWT (remove last 10 characters)
        var truncatedJwt = sdJwtResult.CompactSdJwt[..^10];

        // Act
        var result = _verifier.VerifySdJwt(truncatedJwt, sdJwtResult.DisclosureTokens, _testPublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(SdJwtVerificationStatus.SignatureInvalid, result.Status);
    }

    [Fact]
    public void VerifySdJwtValidationErrorsContainMessage()
    {
        // Arrange
        var invalidJwt = "invalid~format";

        // Act
        var result = _verifier.VerifySdJwt(invalidJwt, Array.Empty<string>(), _testPublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.NotNull(result.ValidationErrors);
        Assert.NotEmpty(result.ValidationErrors);
        Assert.Contains("verification failed", result.ValidationErrors[0], StringComparison.OrdinalIgnoreCase);
    }
}
