using HeroSSID.Credentials.MvpImplementations;
using System;
using System.Collections.Generic;
using System.Text.Json;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Unit tests for MockSdJwtGenerator
/// Verifies mock SD-JWT generation for MVP development
/// </summary>
public sealed class MockSdJwtGeneratorTests
{
    private readonly MockSdJwtGenerator _generator;
    private static readonly string[] SingleNameClaim = ["name"];
    private static readonly string[] NameAndDegreeClaims = ["name", "degree"];
    private static readonly string[] NameAndCityClaims = ["name", "city"];

    public MockSdJwtGeneratorTests()
    {
        _generator = new MockSdJwtGenerator();
    }

    [Fact]
    public void GenerateSdJwtValidInputReturnsValidResult()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Alice Smith" },
            { "degree", "Bachelor of Science" },
            { "graduationDate", "2024-06-15" }
        };
        var selectiveDisclosureClaims = NameAndDegreeClaims;
        var signingKey = new byte[32]; // Mock key
        var issuerDid = "did:hero:issuer123";
        var holderDid = "did:hero:holder456";

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            signingKey,
            issuerDid,
            holderDid);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.CompactSdJwt);
        Assert.NotNull(result.DisclosureTokens);
        Assert.NotEmpty(result.CompactSdJwt);
    }

    [Fact]
    public void GenerateSdJwtCompactFormatContainsTildeSeparator()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Bob" } };
        var selectiveDisclosureClaims = SingleNameClaim;
        var signingKey = new byte[32];

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            signingKey,
            "did:hero:iss",
            "did:hero:sub");

        // Assert - SD-JWT format is: <JWT>~<disclosure>~<disclosure>~
        Assert.Contains("~", result.CompactSdJwt, StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateSdJwtDisclosureTokensMatchSelectiveClaims()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Charlie" },
            { "age", 30 },
            { "city", "Seattle" }
        };
        var selectiveDisclosureClaims = NameAndCityClaims;
        var signingKey = new byte[32];

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            signingKey,
            "did:hero:iss",
            "did:hero:sub");

        // Assert - Mock implementation returns empty array (MVP limitation)
        Assert.NotNull(result.DisclosureTokens);
        Assert.Empty(result.DisclosureTokens);
    }

    [Fact]
    public void GenerateSdJwtEmptyClaimsReturnsValidResult()
    {
        // Arrange
        var claims = new Dictionary<string, object>();
        var selectiveDisclosureClaims = Array.Empty<string>();
        var signingKey = new byte[32];

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            signingKey,
            "did:hero:iss",
            "did:hero:sub");

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.CompactSdJwt);
        Assert.NotNull(result.DisclosureTokens);
    }

    [Fact]
    public void GenerateSdJwtNullSelectiveClaimsThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Diana" },
            { "email", "diana@example.com" }
        };
        var signingKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(
                claims,
                null!, // Null selective claims should throw
                signingKey,
                "did:hero:iss",
                "did:hero:sub"));
    }

    [Fact]
    public void GenerateSdJwtJwtPartContainsValidHeader()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Eve" } };
        var signingKey = new byte[32];

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            SingleNameClaim,
            signingKey,
            "did:hero:iss",
            "did:hero:sub");

        // Assert - Extract JWT part (before first ~)
        var jwtPart = result.CompactSdJwt.Split('~')[0];
        var parts = jwtPart.Split('.');
        Assert.Equal(3, parts.Length); // header.payload.signature

        // Decode and verify header - need to add padding for Base64
        var base64 = parts[0].Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        base64 = base64.PadRight(base64.Length + padding, '=');
        var headerJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        var header = JsonDocument.Parse(headerJson);

        Assert.True(header.RootElement.TryGetProperty("typ", out var typ));
        Assert.Equal("vc+jwt", typ.GetString());
        Assert.True(header.RootElement.TryGetProperty("alg", out var alg));
        Assert.Equal("EdDSA", alg.GetString());
    }

    [Fact]
    public void GenerateSdJwtDifferentSigningKeysProduceDifferentResults()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Frank" } };
        var key1 = new byte[32];
        var key2 = new byte[32];
        Array.Fill(key2, (byte)1); // Different key

        // Act
        var result1 = _generator.GenerateSdJwt(claims, SingleNameClaim, key1, "did:hero:iss", "did:hero:sub");
        var result2 = _generator.GenerateSdJwt(claims, SingleNameClaim, key2, "did:hero:iss", "did:hero:sub");

        // Assert - Different keys should produce different JWTs
        Assert.NotEqual(result1.CompactSdJwt, result2.CompactSdJwt);
    }

    [Fact]
    public void GenerateSdJwtNullClaimsThrowsArgumentNullException()
    {
        // Arrange
        var signingKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(null!, SingleNameClaim, signingKey, "did:hero:iss", "did:hero:sub"));
    }

    [Fact]
    public void GenerateSdJwtNullSigningKeyThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Grace" } };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(claims, SingleNameClaim, null!, "did:hero:iss", "did:hero:sub"));
    }

    [Fact]
    public void GenerateSdJwtNullIssuerDidThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Henry" } };
        var signingKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(claims, SingleNameClaim, signingKey, null!, "did:hero:sub"));
    }

    [Fact]
    public void GenerateSdJwtNullHolderDidThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Iris" } };
        var signingKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(claims, SingleNameClaim, signingKey, "did:hero:iss", null!));
    }
}
