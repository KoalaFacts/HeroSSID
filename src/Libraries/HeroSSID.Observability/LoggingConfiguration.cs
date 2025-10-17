using System.Globalization;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Events;

namespace HeroSSID.Observability;

/// <summary>
/// Configures Serilog for structured logging with file and console outputs
/// </summary>
public static class LoggingConfiguration
{
    /// <summary>
    /// Configures Serilog from application configuration
    /// </summary>
    /// <param name="configuration">Application configuration</param>
    /// <param name="applicationName">Application name for log context</param>
    /// <returns>Configured logger</returns>
    public static ILogger ConfigureSerilog(IConfiguration configuration, string applicationName = "HeroSSID")
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var logPath = configuration["Logging:File:Path"] ?? "./logs/herossid-.log";
        var rollingInterval = configuration["Logging:File:RollingInterval"] ?? "Day";
        var outputTemplate = configuration["Logging:File:OutputTemplate"]
            ?? "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}";

        var minimumLevel = configuration["Logging:LogLevel:Default"] switch
        {
            "Trace" => LogEventLevel.Verbose,
            "Debug" => LogEventLevel.Debug,
            "Information" => LogEventLevel.Information,
            "Warning" => LogEventLevel.Warning,
            "Error" => LogEventLevel.Error,
            "Critical" => LogEventLevel.Fatal,
            _ => LogEventLevel.Information
        };

        return new LoggerConfiguration()
            .MinimumLevel.Is(minimumLevel)
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", applicationName)
            .Enrich.WithProperty("MachineName", Environment.MachineName)
            .WriteTo.Console(
                outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                formatProvider: CultureInfo.InvariantCulture)
            .WriteTo.File(
                path: logPath,
                rollingInterval: ParseRollingInterval(rollingInterval),
                outputTemplate: outputTemplate,
                formatProvider: CultureInfo.InvariantCulture,
                retainedFileCountLimit: 31,
                fileSizeLimitBytes: 100 * 1024 * 1024, // 100 MB
                rollOnFileSizeLimit: true,
                shared: false,
                flushToDiskInterval: TimeSpan.FromSeconds(1))
            .CreateLogger();
    }

    private static RollingInterval ParseRollingInterval(string interval)
    {
        return interval.ToUpperInvariant() switch
        {
            "INFINITE" => RollingInterval.Infinite,
            "YEAR" => RollingInterval.Year,
            "MONTH" => RollingInterval.Month,
            "DAY" => RollingInterval.Day,
            "HOUR" => RollingInterval.Hour,
            "MINUTE" => RollingInterval.Minute,
            _ => RollingInterval.Day
        };
    }
}
