using HeroSSID.Credentials.Implementations;
using HeroSSID.Credentials.SdJwt;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Integration tests for HeroSdJwtGenerator using real HeroSD-JWT NuGet package v1.1.3
/// Tests the production implementation against the ISdJwtGenerator interface with Ed25519 signing
/// </summary>
public sealed class HeroSdJwtGeneratorTests
{
    private readonly HeroSdJwtGenerator _generator;
    private readonly byte[] _testEd25519PrivateKey;
    private readonly byte[] _testEd25519PublicKey;

    public HeroSdJwtGeneratorTests()
    {
        _generator = new HeroSdJwtGenerator();

        // Generate Ed25519 key pair for testing
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using var key = Key.Create(algorithm, keyParams);

        _testEd25519PrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        _testEd25519PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    [Fact]
    public void GenerateSdJwt_WithValidClaims_ReturnsValidSdJwtResult()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Alice" },
            { "email", "alice@example.com" },
            { "age", 30 }
        };
        var selectiveDisclosureClaims = new[] { "email", "age" };
        var issuerDid = "did:key:z6MkTest123";
        var holderDid = "did:key:z6MkHolder456";

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.CompactSdJwt);
        Assert.NotEmpty(result.CompactSdJwt);

        // SD-JWT format should contain tildes (~) separating JWT from disclosures
        Assert.Contains("~", result.CompactSdJwt);

        // Should have disclosure tokens for selective claims
        Assert.NotNull(result.DisclosureTokens);

        // Should have claim digests
        Assert.NotNull(result.ClaimDigests);
    }

    [Fact]
    public void GenerateSdJwt_WithMultipleSelectiveClaims_CreatesMultipleDisclosures()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Bob" },
            { "email", "bob@example.com" },
            { "phone", "+1-555-0100" },
            { "address", "123 Main St" }
        };
        var selectiveDisclosureClaims = new[] { "email", "phone", "address" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Assert
        Assert.NotNull(result.DisclosureTokens);

        // Should create disclosures for selective claims
        // Note: Exact count depends on HeroSD-JWT implementation
        Assert.NotEmpty(result.DisclosureTokens);
    }

    [Fact]
    public void GenerateSdJwt_WithNoSelectiveClaims_ReturnsRegularJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "name", "Charlie" },
            { "role", "admin" }
        };
        var selectiveDisclosureClaims = Array.Empty<string>();
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.CompactSdJwt);
        Assert.NotEmpty(result.CompactSdJwt);
    }

    [Fact]
    public void GenerateSdJwt_WithNullClaims_ThrowsArgumentNullException()
    {
        // Arrange
        Dictionary<string, object>? claims = null;
        var selectiveDisclosureClaims = new[] { "email" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(
                claims!,
                selectiveDisclosureClaims,
                _testHmacKey,
                issuerDid,
                holderDid));
    }

    [Fact]
    public void GenerateSdJwt_WithNullSelectiveDisclosureClaims_ThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Alice" } };
        string[]? selectiveDisclosureClaims = null;
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(
                claims,
                selectiveDisclosureClaims!,
                _testHmacKey,
                issuerDid,
                holderDid));
    }

    [Fact]
    public void GenerateSdJwt_WithNullSigningKey_ThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Alice" } };
        var selectiveDisclosureClaims = new[] { "name" };
        byte[]? signingKey = null;
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _generator.GenerateSdJwt(
                claims,
                selectiveDisclosureClaims,
                signingKey!,
                issuerDid,
                holderDid));
    }

    [Fact]
    public void GenerateSdJwt_WithEmptyIssuerDid_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Alice" } };
        var selectiveDisclosureClaims = new[] { "name" };
        var issuerDid = string.Empty;
        var holderDid = "did:key:z6MkHolder";

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _generator.GenerateSdJwt(
                claims,
                selectiveDisclosureClaims,
                _testHmacKey,
                issuerDid,
                holderDid));
    }

    [Fact]
    public void GenerateSdJwt_WithEmptyHolderDid_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Alice" } };
        var selectiveDisclosureClaims = new[] { "name" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = string.Empty;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _generator.GenerateSdJwt(
                claims,
                selectiveDisclosureClaims,
                _testHmacKey,
                issuerDid,
                holderDid));
    }

    [Fact]
    public void GenerateSdJwt_CompactFormatContainsJwtStructure()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "name", "Test" } };
        var selectiveDisclosureClaims = new[] { "name" };
        var issuerDid = "did:key:z6MkIssuer";
        var holderDid = "did:key:z6MkHolder";

        // Act
        var result = _generator.GenerateSdJwt(
            claims,
            selectiveDisclosureClaims,
            _testEd25519PrivateKey,
            issuerDid,
            holderDid);

        // Assert
        var compactSdJwt = result.CompactSdJwt;

        // JWT should start with header.payload.signature format (base64url encoded)
        var parts = compactSdJwt.Split('~');
        Assert.NotEmpty(parts);

        // First part should be the JWT (header.payload.signature)
        var jwtParts = parts[0].Split('.');
        Assert.True(jwtParts.Length >= 3, "JWT should have at least header, payload, and signature");
    }
}
