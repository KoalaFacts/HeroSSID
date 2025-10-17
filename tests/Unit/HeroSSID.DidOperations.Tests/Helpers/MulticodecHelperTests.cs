using HeroSSID.DidOperations.Helpers;
using System.Security.Cryptography;

#pragma warning disable CA1707 // Test method names should use underscores for readability

namespace HeroSSID.DidOperations.Tests.Helpers;

public class MulticodecHelperTests
{
    [Fact]
    public void AddEd25519Prefix_ShouldAdd0xED01Prefix()
    {
        // Arrange
        var publicKey = new byte[32]; // Ed25519 public key is 32 bytes
        for (int i = 0; i < 32; i++)
        {
            publicKey[i] = (byte)i;
        }

        // Act
        var result = MulticodecHelper.AddEd25519Prefix(publicKey);

        // Assert
        Assert.Equal(34, result.Length); // 32 + 2 bytes prefix
        Assert.Equal(0xed, result[0]);
        Assert.Equal(0x01, result[1]);

        // Verify original key is preserved after prefix
        for (int i = 0; i < 32; i++)
        {
            Assert.Equal((byte)i, result[i + 2]);
        }
    }

    [Fact]
    public void AddEd25519Prefix_WithNullKey_ShouldThrowArgumentNullException()
    {
        // Arrange
        byte[]? publicKey = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MulticodecHelper.AddEd25519Prefix(publicKey!));
    }

    [Fact]
    public void AddEd25519Prefix_WithInvalidKeyLength_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Ed25519 keys must be 32 bytes

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MulticodecHelper.AddEd25519Prefix(invalidKey));
        Assert.Contains("32 bytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RemoveEd25519Prefix_ShouldRemove0xED01Prefix()
    {
        // Arrange
        var multicodecKey = new byte[34];
        multicodecKey[0] = 0xed;
        multicodecKey[1] = 0x01;
        for (int i = 2; i < 34; i++)
        {
            multicodecKey[i] = (byte)(i - 2);
        }

        // Act
        var result = MulticodecHelper.RemoveEd25519Prefix(multicodecKey);

        // Assert
        Assert.Equal(32, result.Length);
        for (int i = 0; i < 32; i++)
        {
            Assert.Equal((byte)i, result[i]);
        }
    }

    [Fact]
    public void RemoveEd25519Prefix_WithNullKey_ShouldThrowArgumentNullException()
    {
        // Arrange
        byte[]? multicodecKey = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MulticodecHelper.RemoveEd25519Prefix(multicodecKey!));
    }

    [Fact]
    public void RemoveEd25519Prefix_WithInvalidPrefix_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidKey = new byte[34];
        invalidKey[0] = 0xff; // Wrong prefix
        invalidKey[1] = 0xff;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MulticodecHelper.RemoveEd25519Prefix(invalidKey));
        Assert.Contains("0xed01", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RemoveEd25519Prefix_WithInvalidLength_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidKey = new byte[16];

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MulticodecHelper.RemoveEd25519Prefix(invalidKey));
        Assert.Contains("34 bytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAndRemovePrefix_ShouldRoundTrip()
    {
        // Arrange
        var originalKey = new byte[32];
        RandomNumberGenerator.Fill(originalKey);

        // Act
        var withPrefix = MulticodecHelper.AddEd25519Prefix(originalKey);
        var removedPrefix = MulticodecHelper.RemoveEd25519Prefix(withPrefix);

        // Assert
        Assert.Equal(originalKey, removedPrefix);
    }
}

#pragma warning restore CA1707
