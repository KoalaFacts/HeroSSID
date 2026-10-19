using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using HeroSSID.DidOperations.DidCreation;

namespace HeroSSID.DidOperations.Tests;

#pragma warning disable CA1707 // Test method naming convention
public sealed class EntropyValidationTests
{
    [Theory]
    [InlineData("balanced", 256, 0.0, null)]
    [InlineData("chi-square-40", 232, 40.0, null)]
    [InlineData("chi-square-40.125", 231, 40.125, "distribution")]
    [InlineData("chi-square-40.75", 228, 40.75, "distribution")]
    [InlineData("unique-128", 128, 0.0, null)]
    [InlineData("unique-127", 127, 0.0, "uniqueness")]
    [InlineData("all-zero", 1, 3840.0, "identical")]
    [InlineData("all-ff", 1, 3840.0, "identical")]
    [InlineData("all-42", 1, 3840.0, "identical")]
    public void ValidateEntropySample_PreservesCurrentBoundariesAndFailures(
        string fixture, int expectedUniqueValues, double expectedChiSquare, string? expectedFailure)
    {
        byte[] sample = CreateSample(fixture);
        Assert.Equal(256, sample.Length);
        Assert.Equal(expectedUniqueValues, sample.Distinct().Count());
        int[] buckets = new int[16];
        foreach (byte value in sample)
        {
            buckets[value / 16]++;
        }

        Assert.Equal(expectedChiSquare, buckets.Sum(count => (count - 16.0) * (count - 16.0) / 16.0));

        // Exercise the actual production validator without acquiring random bytes
        // or exposing a production RNG override. Synthetic samples never create keys.
        MethodInfo? validate = typeof(DidCreationService).GetMethod(
            "ValidateEntropySample", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(validate);

        if (expectedFailure is null)
        {
            Assert.Null(Record.Exception(() => validate.Invoke(null, [sample])));
            return;
        }

        var invocation = Assert.Throws<TargetInvocationException>(() => validate.Invoke(null, [sample]));
        var exception = Assert.IsType<CryptographicException>(invocation.InnerException);
        string expectedMessage = expectedFailure switch
        {
            "distribution" => string.Create(CultureInfo.CurrentCulture,
                $"CRITICAL: System RNG failed distribution test (chi-square: {expectedChiSquare:F2} > 40). Key generation aborted."),
            "uniqueness" => "CRITICAL: System RNG has insufficient entropy - only 127 unique values in 256 bytes (minimum: 128). Key generation aborted.",
            _ => "CRITICAL: System RNG failed entropy test - all bytes identical. Key generation aborted."
        };
        Assert.Equal(expectedMessage, exception.Message);
    }

    private static byte[] CreateSample(string fixture)
    {
        // Values cycle within each bucket, keeping uniqueness independent of the
        // distribution boundary. Every fixture contains exactly 256 bytes.
        return fixture switch
        {
            "balanced" => Enumerable.Range(0, 256).Select(value => (byte)value).ToArray(),
            "chi-square-40" => FromBucketCounts([32, 0, 24, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]),
            "chi-square-40.125" => FromBucketCounts([32, 0, 24, 8, 17, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]),
            "chi-square-40.75" => FromBucketCounts([32, 0, 24, 8, 18, 14, 17, 15, 17, 15, 16, 16, 16, 16, 16, 16]),
            "unique-128" => UniqueBoundarySample(),
            "unique-127" => UniqueBoundarySample().Select(value => value == 247 ? (byte)246 : value).ToArray(),
            "all-zero" => new byte[256],
            "all-ff" => Enumerable.Repeat((byte)0xFF, 256).ToArray(),
            "all-42" => Enumerable.Repeat((byte)0x42, 256).ToArray(),
            _ => throw new ArgumentException("Unknown entropy fixture", nameof(fixture))
        };
    }

    private static byte[] FromBucketCounts(int[] counts) => counts
        .SelectMany((count, bucket) => Enumerable.Range(0, count)
            .Select(index => (byte)(bucket * 16 + index % 16)))
        .ToArray();

    private static byte[] UniqueBoundarySample() => Enumerable.Range(0, 16)
        .SelectMany(bucket => Enumerable.Range(0, 16)
            .Select(index => (byte)(bucket * 16 + index % 8)))
        .ToArray();
}
