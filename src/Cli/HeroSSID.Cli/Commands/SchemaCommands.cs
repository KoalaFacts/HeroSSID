using System.CommandLine;
using Spectre.Console;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Credential schema CLI commands
/// </summary>
internal static class SchemaCommands
{
    public static Command CreateCommand(IServiceProvider serviceProvider)
    {
        var schemaCommand = new Command("schema", "Credential schema operations");

        var publishCommand = new Command("publish", "Publish a new credential schema");
        var nameOption = new Option<string>(
            name: "--name",
            description: "Schema name") { IsRequired = true };
        var versionOption = new Option<string>(
            name: "--version",
            description: "Schema version (semantic versioning)",
            getDefaultValue: () => "1.0.0");
        var attributesOption = new Option<string[]>(
            name: "--attributes",
            description: "Attribute names (comma-separated)") { IsRequired = true };

        publishCommand.AddOption(nameOption);
        publishCommand.AddOption(versionOption);
        publishCommand.AddOption(attributesOption);

        publishCommand.SetHandler(async (string name, string version, string[] attributes) =>
        {
            await AnsiConsole.Status()
                .StartAsync($"Publishing schema '{name}' v{version}...", async ctx =>
                {
                    ctx.Spinner(Spinner.Known.Dots);
                    ctx.SpinnerStyle(Style.Parse("blue"));

                    // TODO: Implement schema publishing logic
                    await Task.Delay(1500).ConfigureAwait(false); // Simulate work

                    AnsiConsole.MarkupLine("[green]Success:[/] Schema published!");
                    AnsiConsole.MarkupLine($"[dim]Schema: {name} v{version}[/]");
                    AnsiConsole.MarkupLine($"[dim]Attributes: {string.Join(", ", attributes)}[/]");
                    AnsiConsole.MarkupLine("[dim]Schema ID: https://example.com/schemas/{name}/v{version}[/]");
                }).ConfigureAwait(false);
        }, nameOption, versionOption, attributesOption);

        schemaCommand.AddCommand(publishCommand);

        return schemaCommand;
    }
}
