using System.Reflection;
using System.Security.Cryptography;
using HeroSSID.DidOperations.DidCreation;
using NSec.Cryptography;

namespace HeroSSID.DidOperations.Tests;

public sealed class EntropyValidationTests
{
    [Fact]
    public void PlausibleRandomDistributionIsNotASeparateKeyCreationGate()
    {
        // A uniformly random 256-byte sample can have these bucket counts.
        // The old per-DID chi-square threshold (> 40) rejected this exact
        // possible result, independently of whether NSec could create a key.
        int[] counts = [32, 0, 24, 8, 17, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16];
        byte[] sample = counts.SelectMany((count, bucket) =>
            Enumerable.Range(0, count).Select(index => (byte)(bucket * 16 + index % 16))).ToArray();

        Assert.Equal(256, sample.Length);
        Assert.Equal(231, sample.Distinct().Count());
        Assert.Equal(40.125, counts.Sum(count => (count - 16.0) * (count - 16.0) / 16.0));

        // Key creation must rely on NSec's cryptographic provider, not on a
        // small-sample health heuristic that can reject a healthy provider.
        Assert.Null(typeof(DidCreationService).GetMethod(
            "ValidateSystemEntropy", BindingFlags.NonPublic | BindingFlags.Static));
        Assert.Null(typeof(DidCreationService).GetMethod(
            "ValidateEntropySample", BindingFlags.NonPublic | BindingFlags.Static));
    }

    [Fact]
    public void ExportedValidEd25519KeyPairPassesRealSigningSelfCheck()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);

        try
        {
            (byte[] returnedPublic, byte[] returnedPrivate) = FinishGeneratedKeyPair(publicKey, privateKey);
            Assert.Same(publicKey, returnedPublic);
            Assert.Same(privateKey, returnedPrivate);
            Assert.Equal(32, returnedPublic.Length);
            Assert.Equal(32, returnedPrivate.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    [Theory]
    [InlineData("public")]
    [InlineData("private")]
    [InlineData("both")]
    public void AllZeroExportedKeyMaterialIsRejectedAndScrubbed(string zeroField)
    {
        byte[] publicKey = Enumerable.Repeat((byte)0x31, 32).ToArray();
        byte[] privateKey = Enumerable.Repeat((byte)0x42, 32).ToArray();

        if (zeroField is "public" or "both")
        {
            publicKey.AsSpan().Clear();
        }
        if (zeroField is "private" or "both")
        {
            privateKey.AsSpan().Clear();
        }

        var exception = Assert.Throws<TargetInvocationException>(
            () => FinishGeneratedKeyPair(publicKey, privateKey));
        var cryptographicException = Assert.IsType<CryptographicException>(exception.InnerException);
        Assert.Contains("all-zero", cryptographicException.Message, StringComparison.OrdinalIgnoreCase);
        Assert.All(publicKey, value => Assert.Equal((byte)0, value));
        Assert.All(privateKey, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void MismatchedPublicAndPrivateKeyAreRejectedAndScrubbed()
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using Key first = Key.Create(SignatureAlgorithm.Ed25519, parameters);
        using Key second = Key.Create(SignatureAlgorithm.Ed25519, parameters);
        byte[] publicKey = second.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] privateKey = first.Export(KeyBlobFormat.RawPrivateKey);

        var exception = Assert.Throws<TargetInvocationException>(
            () => FinishGeneratedKeyPair(publicKey, privateKey));
        var cryptographicException = Assert.IsType<CryptographicException>(exception.InnerException);
        Assert.Contains("signature verification failed", cryptographicException.Message, StringComparison.OrdinalIgnoreCase);
        Assert.All(publicKey, value => Assert.Equal((byte)0, value));
        Assert.All(privateKey, value => Assert.Equal((byte)0, value));
    }

    [Theory]
    [InlineData(31, 32)]
    [InlineData(32, 31)]
    public void IncorrectExportedKeyLengthsAreRejectedAndScrubbed(int publicLength, int privateLength)
    {
        byte[] publicKey = Enumerable.Repeat((byte)0x31, publicLength).ToArray();
        byte[] privateKey = Enumerable.Repeat((byte)0x42, privateLength).ToArray();

        var exception = Assert.Throws<TargetInvocationException>(
            () => FinishGeneratedKeyPair(publicKey, privateKey));
        var cryptographicException = Assert.IsType<CryptographicException>(exception.InnerException);
        Assert.Contains("invalid length", cryptographicException.Message, StringComparison.OrdinalIgnoreCase);
        Assert.All(publicKey, value => Assert.Equal((byte)0, value));
        Assert.All(privateKey, value => Assert.Equal((byte)0, value));
    }

    private static (byte[] publicKey, byte[] privateKey) FinishGeneratedKeyPair(
        byte[] publicKey, byte[] privateKey)
    {
        MethodInfo method = Assert.IsAssignableFrom<MethodInfo>(
            typeof(DidCreationService).GetMethod("FinishGeneratedKeyPair",
                BindingFlags.NonPublic | BindingFlags.Static));
        return ((byte[] publicKey, byte[] privateKey))method.Invoke(
            null, [SignatureAlgorithm.Ed25519, publicKey, privateKey])!;
    }
}
