using System.CommandLine;
using HeroSSID.Cli.Commands;
using HeroSSID.Cli.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console;

// Build configuration
IConfiguration configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .Build();

// Setup dependency injection
ServiceCollection services = new ServiceCollection();
services.AddSingleton(configuration);
services.AddLogging(); // Basic logging setup

DependencyInjectionConfig.ConfigureServices(services, configuration);

IServiceProvider serviceProvider = services.BuildServiceProvider();

// Setup root command
var rootCommand = new RootCommand("HeroSSID CLI - Decentralized Identity Management");

// Add DID commands
rootCommand.AddCommand(DidCommands.CreateCommand(serviceProvider));
rootCommand.AddCommand(CredentialCommands.CreateCommand(serviceProvider));

// Keep malformed --claim-value arguments out of parser-generated diagnostics.
// Authentication and claim comparisons still happen in the command handler.
if (!CredentialCommands.CanInvokePinnedClaimWithoutEchoingPolicy(args))
{
    await Console.Error.WriteLineAsync(
        "VC1.1 signed claim rejected: malformed CLI arguments. No values released.")
        .ConfigureAwait(false);
    return 1;
}

// Display banner
AnsiConsole.Write(
    new FigletText("HeroSSID")
        .LeftJustified()
        .Color(Color.Cyan1));

AnsiConsole.MarkupLine("[dim]Issuer signature verification is not holder proof, revocation, identity or authorization[/]");
AnsiConsole.WriteLine();

// Execute command
return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
