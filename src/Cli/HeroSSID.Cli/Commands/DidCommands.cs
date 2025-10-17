using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// DID-related CLI commands
/// </summary>
internal static class DidCommands
{
    public static Command CreateCommand(IServiceProvider serviceProvider)
    {
        var didCommand = new Command("did", "DID (Decentralized Identifier) operations");

        var createCommand = new Command("create", "Create a new DID");
        createCommand.SetHandler(async () =>
        {
            await AnsiConsole.Status()
                .StartAsync("Creating DID...", async ctx =>
                {
                    ctx.Spinner(Spinner.Known.Dots);
                    ctx.SpinnerStyle(Style.Parse("green"));

                    // TODO: Implement DID creation logic
                    await Task.Delay(1000).ConfigureAwait(false); // Simulate work

                    AnsiConsole.MarkupLine("[green]Success:[/] DID created!");
                    AnsiConsole.MarkupLine("[dim]DID: did:web:example.com:user:alice[/]");
                    AnsiConsole.MarkupLine("[dim]Public Key: z6Mkf5rGMo...[/]");
                }).ConfigureAwait(false);
        });

        var listCommand = new Command("list", "List all DIDs");
        listCommand.SetHandler(() =>
        {
            var table = new Table();
            table.AddColumn("DID");
            table.AddColumn("Status");
            table.AddColumn("Created");

            table.AddRow("did:web:example.com:user:alice", "[green]Active[/]", "2025-10-15");
            table.AddRow("did:key:z6Mkf5rGMoLAM4HdgjE...", "[green]Active[/]", "2025-10-16");

            AnsiConsole.Write(table);
        });

        didCommand.AddCommand(createCommand);
        didCommand.AddCommand(listCommand);

        return didCommand;
    }
}
