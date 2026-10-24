using HeroSSID.Api.Features.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace HeroSSID.Api.Tests;

public sealed class JwtSigningSettingsTests
{
    [Fact]
    public void DevelopmentRequiresSecretButAllowsLocalIssuerAudienceDefaults()
    {
        var settings = JwtSigningSettings.FromConfiguration(Configuration(("Jwt:Secret", new string('k', 32))), new TestEnvironment("Development"));

        Assert.Equal(new string('k', 32), settings.Secret);
        Assert.Equal("https://herossid.api", settings.Issuer);
        Assert.Equal("https://herossid.api", settings.Audience);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Development")]
    public void EveryEnvironmentRequiresAnExplicitSigningSecret(string environmentName)
    {
        var config = Configuration(
            ("Jwt:Issuer", "https://issuer.example"),
            ("Jwt:Audience", "https://api.example"));

        var failure = Assert.Throws<InvalidOperationException>(
            () => JwtSigningSettings.FromConfiguration(config, new TestEnvironment(environmentName)));

        Assert.Contains("Jwt:Secret", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Development")]
    public void EveryEnvironmentRejectsExampleSigningSecret(string environmentName)
    {
        var failure = Assert.Throws<InvalidOperationException>(() => JwtSigningSettings.FromConfiguration(
            ValidProductionConfiguration(secret: JwtSigningSettings.DevelopmentSecret),
            new TestEnvironment(environmentName)));

        Assert.Contains("example", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Development")]
    public void EveryEnvironmentRejectsHmacEquivalentZeroPaddedExampleKeys(string environmentName)
    {
        // HMAC-SHA256 pads the public example key with zero bytes to a 64-byte block.
        // Suffixing that key with literal NULs produces exactly the same MAC.
        foreach (var suffix in new[] { "\0", "\0\0", "\0\0\0" })
        {
            var config = ValidProductionConfiguration(
                secret: JwtSigningSettings.DevelopmentSecret + suffix);

            var failure = Assert.Throws<InvalidOperationException>(() =>
                JwtSigningSettings.FromConfiguration(config, new TestEnvironment(environmentName)));

            Assert.Contains("NUL", failure.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("short-secret")]
    [InlineData(" ")]
    public void ProductionRejectsMissingOrUndersizedKeys(string secret)
    {
        Assert.Throws<InvalidOperationException>(() => JwtSigningSettings.FromConfiguration(
            ValidProductionConfiguration(secret: secret),
            new TestEnvironment("Production")));
    }

    [Theory]
    [InlineData("Jwt:Issuer")]
    [InlineData("Jwt:Audience")]
    public void ProductionRequiresAnExplicitIssuerAndAudience(string missingSetting)
    {
        var config = ValidProductionConfiguration();
        config[missingSetting] = null;

        var failure = Assert.Throws<InvalidOperationException>(
            () => JwtSigningSettings.FromConfiguration(config, new TestEnvironment("Production")));

        Assert.Contains(missingSetting, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ProductionAcceptsUniqueExplicitSettings()
    {
        var settings = JwtSigningSettings.FromConfiguration(
            ValidProductionConfiguration(),
            new TestEnvironment("Production"));

        Assert.Equal(new string('k', 32), settings.Secret);
        Assert.Equal("https://issuer.example", settings.Issuer);
        Assert.Equal("https://api.example", settings.Audience);
    }

    [Theory]
    [InlineData("Jwt:Issuer", "")]
    [InlineData("Jwt:Issuer", " ")]
    [InlineData("Jwt:Audience", "")]
    [InlineData("Jwt:Audience", " ")]
    public void DevelopmentRejectsExplicitlyEmptyIssuerOrAudience(string setting, string value)
    {
        var config = ValidProductionConfiguration();
        config[setting] = value;
        var failure = Assert.Throws<InvalidOperationException>(() =>
            JwtSigningSettings.FromConfiguration(config, new TestEnvironment("Development")));
        Assert.Contains(setting, failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public void EveryEnvironmentRejectsNulInOtherwiseUniqueSigningSecret(string environmentName)
    {
        var config = ValidProductionConfiguration(new string('k', 32) + "\0");
        var failure = Assert.Throws<InvalidOperationException>(() =>
            JwtSigningSettings.FromConfiguration(config, new TestEnvironment(environmentName)));
        Assert.Contains("NUL", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DiagnosticStringRepresentationNeverIncludesTheSigningSecret()
    {
        var settings = JwtSigningSettings.FromConfiguration(
            ValidProductionConfiguration(),
            new TestEnvironment("Production"));

        Assert.DoesNotContain(settings.Secret, settings.ToString(), StringComparison.Ordinal);
    }

    private static IConfigurationRoot ValidProductionConfiguration(string? secret = null) => Configuration(
        ("Jwt:Secret", secret ?? new string('k', 32)),
        ("Jwt:Issuer", "https://issuer.example"),
        ("Jwt:Audience", "https://api.example"));

    private static IConfigurationRoot Configuration(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.ToDictionary(item => item.Key, item => item.Value))
            .Build();

    private sealed class TestEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "HeroSSID.Api.Tests";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
