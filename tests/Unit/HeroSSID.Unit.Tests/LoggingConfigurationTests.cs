using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using HeroSSID.Observability;
using Microsoft.Extensions.Configuration;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace HeroSSID.Unit.Tests;

// SelfLog is process-global. Keep its failure-path check isolated from other collections.
[CollectionDefinition(nameof(LoggingTestIsolation), DisableParallelization = true)]
[SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "xUnit requires collection definitions to be public.")]
public sealed class LoggingTestIsolation;

[Collection(nameof(LoggingTestIsolation))]
public sealed class LoggingConfigurationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "herossid-logging-" + Guid.NewGuid().ToString("N"));

    public LoggingConfigurationTests()
    {
        Directory.CreateDirectory(_directory);
    }

    [Fact]
    public void WritesConfiguredTemplateUsingInvariantCulture()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            using (var logger = CreateLogger(outputTemplate: "{Level:u3}|{Application}|{Message:lj}{NewLine}"))
            {
                logger.Information("Amount {Amount:N2}", 12.5m);
            }

            Assert.Equal("INF|LoggingTests|Amount 12.50" + Environment.NewLine, File.ReadAllText(LogPath));
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Theory]
    [InlineData("Trace", LogEventLevel.Verbose)]
    [InlineData("Debug", LogEventLevel.Debug)]
    [InlineData("Information", LogEventLevel.Information)]
    [InlineData("Warning", LogEventLevel.Warning)]
    [InlineData("Error", LogEventLevel.Error)]
    [InlineData("Critical", LogEventLevel.Fatal)]
    [InlineData("unknown", LogEventLevel.Information)]
    public void PreservesConfiguredMinimumLevel(string configuredLevel, LogEventLevel minimumLevel)
    {
        using (var logger = CreateLogger(minimumLevel: configuredLevel))
        {
            if (minimumLevel > LogEventLevel.Verbose)
            {
                logger.Write(minimumLevel - 1, "Filtered");
            }

            logger.Write(minimumLevel, "Accepted");
        }

        Assert.Equal("Accepted" + Environment.NewLine, File.ReadAllText(LogPath));
    }

    [Fact]
    public void PreservesFrameworkWarningOverrides()
    {
        using (var logger = CreateLogger(minimumLevel: "Trace"))
        {
            logger.ForContext("SourceContext", "Microsoft.Hosting").Information("Filtered Microsoft");
            logger.ForContext("SourceContext", "System.Net").Information("Filtered System");
            logger.ForContext("SourceContext", "Microsoft.Hosting").Warning("Microsoft warning");
            logger.ForContext("SourceContext", "System.Net").Warning("System warning");
            logger.ForContext("SourceContext", "HeroSSID").Debug("Application debug");
        }

        Assert.Equal(
            string.Join(Environment.NewLine, "Microsoft warning", "System warning", "Application debug", ""),
            File.ReadAllText(LogPath));
    }

    [Theory]
    [InlineData("Infinite", "")]
    [InlineData("Year", "yyyy")]
    [InlineData("Month", "yyyyMM")]
    [InlineData("Day", "yyyyMMdd")]
    [InlineData("Hour", "yyyyMMddHH")]
    [InlineData("Minute", "yyyyMMddHHmm")]
    [InlineData("unknown", "yyyyMMdd")]
    [InlineData(null, "yyyyMMdd")]
    public void PreservesConfiguredRollingFileNames(string? interval, string dateFormat)
    {
        ArgumentNullException.ThrowIfNull(dateFormat);
        var before = DateTime.Now;
        using (var logger = CreateLogger(rollingInterval: interval))
        {
            logger.Information("Rolling event");
        }
        var after = DateTime.Now;

        var path = Assert.Single(Directory.GetFiles(_directory));
        var expectedBefore = "herossid-" + (dateFormat.Length == 0 ? "" : before.ToString(dateFormat, CultureInfo.InvariantCulture)) + ".log";
        var expectedAfter = "herossid-" + (dateFormat.Length == 0 ? "" : after.ToString(dateFormat, CultureInfo.InvariantCulture)) + ".log";
        Assert.Contains(Path.GetFileName(path), new[] { expectedBefore, expectedAfter });
        Assert.Equal("Rolling event" + Environment.NewLine, File.ReadAllText(path));
    }

    [Fact]
    public void AppendsAfterDisposalAndReopen()
    {
        using (var logger = CreateLogger())
        {
            logger.Information("First event");
            // The production one-second flush interval remains configured; unbuffered
            // writes must also be visible to a reader while the logger is alive.
            using var stream = new FileStream(LogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            Assert.Equal("First event" + Environment.NewLine, reader.ReadToEnd());
        }

        using (var logger = CreateLogger())
        {
            logger.Information("Second event");
        }

        Assert.Equal("First event" + Environment.NewLine + "Second event" + Environment.NewLine, File.ReadAllText(LogPath));
        using var exclusive = new FileStream(LogPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(exclusive.CanWrite);
    }

    [Fact]
    public void RetainsOnlyThirtyOneRollingFiles()
    {
        for (var day = 1; day <= 32; day++)
        {
            var date = new DateTime(2000, 1, 1).AddDays(day - 1);
            File.WriteAllText(Path.Combine(_directory, "herossid-" + date.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".log"), "old");
        }

        using (var logger = CreateLogger(rollingInterval: "Day"))
        {
            logger.Information("Current event");
        }

        Assert.Equal(31, Directory.GetFiles(_directory).Length);
        Assert.False(File.Exists(Path.Combine(_directory, "herossid-20000101.log")));
        Assert.False(File.Exists(Path.Combine(_directory, "herossid-20000102.log")));
        Assert.True(File.Exists(Path.Combine(_directory, "herossid-20000103.log")));
    }

    [Fact]
    public void RollsAtConfiguredSizeWithoutTruncatingAnEvent()
    {
        const long limit = 100 * 1024 * 1024;
        using (var initial = File.Create(LogPath))
        {
            // Pre-size the file to exercise the real limit without generating large log messages.
            initial.SetLength(limit - 1);
        }

        using (var logger = CreateLogger())
        {
            logger.Information("Boundary event");
            logger.Information("Next event");
        }

        using (var original = File.OpenRead(LogPath))
        {
            original.Seek(limit - 1, SeekOrigin.Begin);
            using var reader = new StreamReader(original);
            Assert.Equal("Boundary event" + Environment.NewLine, reader.ReadToEnd());
        }

        Assert.Equal("Next event" + Environment.NewLine, File.ReadAllText(Path.Combine(_directory, "herossid-_001.log")));
        Assert.Equal(2, Directory.GetFiles(_directory).Length);
    }

    [Fact]
    public void ReportsAnUnusablePathWithoutThrowingFromApplicationLogging()
    {
        var parentFile = Path.Combine(_directory, "not-a-directory");
        File.WriteAllText(parentFile, "preserve");
        using var diagnostics = new StringWriter(CultureInfo.InvariantCulture);
        SelfLog.Enable(TextWriter.Synchronized(diagnostics));
        try
        {
            using var logger = CreateLogger(path: Path.Combine(parentFile, "log.txt"));
            logger.Information("Cannot reach file");
        }
        finally
        {
            SelfLog.Disable();
        }

        Assert.Contains("not-a-directory", diagnostics.ToString(), StringComparison.Ordinal);
        Assert.Equal("preserve", File.ReadAllText(parentFile));
        Assert.Single(Directory.GetFiles(_directory));
    }

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
    }

    private string LogPath => Path.Combine(_directory, "herossid-.log");

    private Logger CreateLogger(string? rollingInterval = "Infinite", string outputTemplate = "{Message:lj}{NewLine}", string? minimumLevel = null, string? path = null)
    {
        using var configuration = Assert.IsType<ConfigurationRoot>(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Logging:File:Path"] = path ?? LogPath,
            ["Logging:File:RollingInterval"] = rollingInterval,
            ["Logging:File:OutputTemplate"] = outputTemplate,
            ["Logging:LogLevel:Default"] = minimumLevel
        }).Build());

        return Assert.IsType<Logger>(LoggingConfiguration.ConfigureSerilog(configuration, "LoggingTests"));
    }
}
