using HeroSSID.Credentials.Utilities;
using NSec.Cryptography;
using System;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Tests for Ed25519 JWT signing and verification
/// </summary>
public sealed class Ed25519JwtHelperTests
{
    [Fact]
    public void CreateSignedJwtValidInputsReturnsJwt()
    {
        // Arrange
        var (privateKey, publicKey) = GenerateTestKeyPair();
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";

        // Act
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);

        // Assert
        Assert.NotNull(jwt);
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length); // header.payload.signature
    }

    [Fact]
    public void CreateSignedJwtAndVerifySucceeds()
    {
        // Arrange
        var (privateKey, publicKey) = GenerateTestKeyPair();
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";

        // Act
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);
        var isValid = Ed25519JwtHelper.VerifySignedJwt(jwt, publicKey);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifySignedJwtTamperedPayloadReturnsFalse()
    {
        // Arrange
        var (privateKey, publicKey) = GenerateTestKeyPair();
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);

        // Tamper with the JWT by replacing the payload
        var parts = jwt.Split('.');
        var tamperedJwt = $"{parts[0]}.TAMPERED.{parts[2]}";

        // Act
        var isValid = Ed25519JwtHelper.VerifySignedJwt(tamperedJwt, publicKey);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void VerifySignedJwtWrongPublicKeyReturnsFalse()
    {
        // Arrange
        var (privateKey, _) = GenerateTestKeyPair();
        var (_, wrongPublicKey) = GenerateTestKeyPair(); // Different key pair
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);

        // Act
        var isValid = Ed25519JwtHelper.VerifySignedJwt(jwt, wrongPublicKey);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ExtractPayloadValidJwtReturnsPayload()
    {
        // Arrange
        var (privateKey, _) = GenerateTestKeyPair();
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);

        // Act
        var extractedPayload = Ed25519JwtHelper.ExtractPayload(jwt);

        // Assert
        Assert.Equal(payload, extractedPayload);
    }

    [Fact]
    public void ExtractHeaderValidJwtReturnsHeader()
    {
        // Arrange
        var (privateKey, _) = GenerateTestKeyPair();
        var header = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";
        var payload = "{\"iss\":\"test\",\"sub\":\"user123\"}";
        var jwt = Ed25519JwtHelper.CreateSignedJwt(header, payload, privateKey);

        // Act
        var extractedHeader = Ed25519JwtHelper.ExtractHeader(jwt);

        // Assert
        Assert.Equal(header, extractedHeader);
    }

    [Fact]
    public void CreateSignedJwtNullHeaderThrowsArgumentNullException()
    {
        // Arrange
        var (privateKey, _) = GenerateTestKeyPair();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Ed25519JwtHelper.CreateSignedJwt(null!, "{}", privateKey));
    }

    [Fact]
    public void CreateSignedJwtNullPayloadThrowsArgumentNullException()
    {
        // Arrange
        var (privateKey, _) = GenerateTestKeyPair();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Ed25519JwtHelper.CreateSignedJwt("{}", null!, privateKey));
    }

    [Fact]
    public void CreateSignedJwtInvalidPrivateKeyLengthThrowsArgumentException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Wrong length

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Ed25519JwtHelper.CreateSignedJwt("{}", "{}", invalidKey));

        Assert.Contains("32 bytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifySignedJwtMalformedJwtReturnsFalse()
    {
        // Arrange
        var (_, publicKey) = GenerateTestKeyPair();
        var malformedJwt = "invalid.jwt"; // Only 2 parts

        // Act
        var isValid = Ed25519JwtHelper.VerifySignedJwt(malformedJwt, publicKey);

        // Assert
        Assert.False(isValid);
    }

    private static (byte[] privateKey, byte[] publicKey) GenerateTestKeyPair()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

        using var key = Key.Create(algorithm, keyParams);
        var privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        return (privateKey, publicKey);
    }
}
