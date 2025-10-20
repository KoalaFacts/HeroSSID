using HeroSSID.Credentials.Crypto;
using Microsoft.IdentityModel.Tokens;
using NSec.Cryptography;
using System;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// TDD tests for Ed25519JwtConverter - T009
/// Tests written BEFORE implementation following red-green-refactor cycle
/// </summary>
public sealed class Ed25519JwtConverterTests
{
    [Fact]
    public void ConvertToSecurityKey_ValidNSecPublicKey_ReturnsEd25519SecurityKey()
    {
        // Arrange
        var publicKeyBytes = GenerateTestPublicKey();

        // Act
        var securityKey = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(publicKeyBytes);

        // Assert
        Assert.NotNull(securityKey);
        Assert.IsType<Ed25519SecurityKey>(securityKey);
    }

    [Fact]
    public void ConvertToSecurityKey_ValidPublicKey_KeyIdIsSet()
    {
        // Arrange
        var publicKeyBytes = GenerateTestPublicKey();

        // Act
        var securityKey = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(publicKeyBytes);

        // Assert
        Assert.NotNull(securityKey.KeyId);
        Assert.NotEmpty(securityKey.KeyId);
    }

    [Fact]
    public void ConvertToSecurityKey_NullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(null!));
    }

    [Fact]
    public void ConvertToSecurityKey_EmptyArray_ThrowsArgumentException()
    {
        // Arrange
        var emptyArray = Array.Empty<byte>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(emptyArray));
    }

    [Fact]
    public void ConvertToSecurityKey_InvalidKeyLength_ThrowsArgumentException()
    {
        // Arrange
        var invalidLengthKey = new byte[16]; // Ed25519 public keys are 32 bytes

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(invalidLengthKey));
    }

    [Fact]
    public void ConvertToSigningCredentials_ValidNSecPrivateKey_ReturnsSigningCredentials()
    {
        // Arrange
        var privateKeyBytes = GenerateTestPrivateKey();

        // Act
        var signingCredentials = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(privateKeyBytes);

        // Assert
        Assert.NotNull(signingCredentials);
        Assert.IsType<SigningCredentials>(signingCredentials);
    }

    [Fact]
    public void ConvertToSigningCredentials_ValidPrivateKey_AlgorithmIsEdDSA()
    {
        // Arrange
        var privateKeyBytes = GenerateTestPrivateKey();

        // Act
        var signingCredentials = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(privateKeyBytes);

        // Assert
        Assert.Equal("EdDSA", signingCredentials.Algorithm);
    }

    [Fact]
    public void ConvertToSigningCredentials_ValidPrivateKey_KeyIsEd25519SecurityKey()
    {
        // Arrange
        var privateKeyBytes = GenerateTestPrivateKey();

        // Act
        var signingCredentials = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(privateKeyBytes);

        // Assert
        Assert.IsType<Ed25519SecurityKey>(signingCredentials.Key);
    }

    [Fact]
    public void ConvertToSigningCredentials_NullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(null!));
    }

    [Fact]
    public void ConvertToSigningCredentials_EmptyArray_ThrowsArgumentException()
    {
        // Arrange
        var emptyArray = Array.Empty<byte>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(emptyArray));
    }

    [Fact]
    public void ConvertToSigningCredentials_InvalidKeyLength_ThrowsArgumentException()
    {
        // Arrange
        var invalidLengthKey = new byte[16]; // Ed25519 private keys are 32 bytes

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSigningCredentials(invalidLengthKey));
    }

    [Fact]
    public void ConvertToSecurityKey_TwoCallsWithSamePublicKey_ReturnDifferentKeyIds()
    {
        // Arrange
        var publicKeyBytes = GenerateTestPublicKey();

        // Act
        var securityKey1 = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(publicKeyBytes);
        var securityKey2 = HeroSSID.Credentials.Utilities.Ed25519JwtConverter.ConvertToSecurityKey(publicKeyBytes);

        // Assert
        // KeyId should be unique per call (includes timestamp or random component)
        Assert.NotEqual(securityKey1.KeyId, securityKey2.KeyId);
    }

    private static byte[] GenerateTestPublicKey()
    {
        // Generate a valid Ed25519 public key using NSec
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

        using var key = Key.Create(algorithm, keyParams);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    private static byte[] GenerateTestPrivateKey()
    {
        // Generate a valid Ed25519 private key using NSec
        var algorithm = SignatureAlgorithm.Ed25519;
        var keyParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

        using var key = Key.Create(algorithm, keyParams);
        return key.Export(KeyBlobFormat.RawPrivateKey);
    }
}
