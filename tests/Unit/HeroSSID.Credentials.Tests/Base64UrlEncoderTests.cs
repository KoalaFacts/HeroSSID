using HeroSSID.Credentials.Utilities;
using System;
using System.Text;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// Tests for Base64Url encoding/decoding utility
/// </summary>
public sealed class Base64UrlEncoderTests
{
    [Fact]
    public void EncodeByteArrayReturnsBase64UrlString()
    {
        // Arrange
        var input = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"

        // Act
        var result = Base64UrlEncoder.Encode(input);

        // Assert
        Assert.NotNull(result);
        Assert.DoesNotContain('+', result);
        Assert.DoesNotContain('/', result);
        Assert.DoesNotContain('=', result);
    }

    [Fact]
    public void EncodeStringReturnsBase64UrlString()
    {
        // Arrange
        var input = "Hello World";

        // Act
        var result = Base64UrlEncoder.Encode(input);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("SGVsbG8gV29ybGQ", result);
    }

    [Fact]
    public void DecodeBytesValidBase64UrlReturnsOriginalBytes()
    {
        // Arrange
        var original = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        var encoded = Base64UrlEncoder.Encode(original);

        // Act
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);

        // Assert
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void DecodeStringValidBase64UrlReturnsOriginalString()
    {
        // Arrange
        var original = "Hello World";
        var encoded = Base64UrlEncoder.Encode(original);

        // Act
        var decoded = Base64UrlEncoder.DecodeString(encoded);

        // Assert
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void RoundTripByteArrayPreservesData()
    {
        // Arrange
        var original = Encoding.UTF8.GetBytes("Test data with special chars: +/=");

        // Act
        var encoded = Base64UrlEncoder.Encode(original);
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);

        // Assert
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void RoundTripStringPreservesData()
    {
        // Arrange
        var original = "JWT payload: {\"iss\":\"did:web:example.com\",\"sub\":\"holder123\"}";

        // Act
        var encoded = Base64UrlEncoder.Encode(original);
        var decoded = Base64UrlEncoder.DecodeString(encoded);

        // Assert
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void EncodeNullByteArrayThrowsArgumentNullException()
    {
        // Arrange
        byte[]? input = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode(input!));
    }

    [Fact]
    public void EncodeNullStringThrowsArgumentNullException()
    {
        // Arrange
        string? input = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode(input!));
    }

    [Fact]
    public void DecodeBytesNullInputThrowsArgumentNullException()
    {
        // Arrange
        string? input = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeBytes(input!));
    }

    [Fact]
    public void DecodeStringNullInputThrowsArgumentNullException()
    {
        // Arrange
        string? input = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeString(input!));
    }

    [Fact]
    public void EncodeEmptyByteArrayReturnsEmptyString()
    {
        // Arrange
        var input = Array.Empty<byte>();

        // Act
        var result = Base64UrlEncoder.Encode(input);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void EncodeEmptyStringReturnsEmptyString()
    {
        // Arrange
        var input = string.Empty;

        // Act
        var result = Base64UrlEncoder.Encode(input);

        // Assert
        Assert.Equal(string.Empty, result);
    }
}
