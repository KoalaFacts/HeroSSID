using System.CommandLine;
using HeroSSID.DidOperations.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// DID-related CLI commands
/// </summary>
#pragma warning disable CA1031 // Do not catch general exception types - CLI needs to catch all for UX
#pragma warning disable CA1308 // In UI code, ToLowerInvariant is acceptable for display normalization
internal static class DidCommands
{
    public static Command CreateCommand(IServiceProvider serviceProvider)
    {
        var didCommand = new Command("did", "DID (Decentralized Identifier) operations");

        var createCommand = new Command("create", "Create a new W3C-compliant DID");
        createCommand.SetHandler(async () =>
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

                await AnsiConsole.Status()
                    .StartAsync("Creating DID...", async ctx =>
                    {
                        ctx.Spinner(Spinner.Known.Dots);
                        ctx.SpinnerStyle(Style.Parse("green"));

                        // Get DID creation service from DI container
                        using IServiceScope scope = serviceProvider.CreateScope();
                        IDidCreationService didService = scope.ServiceProvider.GetRequiredService<IDidCreationService>();

                        // Create DID using the actual service with timeout
                        var result = await didService.CreateDidAsync(cts.Token).ConfigureAwait(false);

                        AnsiConsole.MarkupLine("[green]✓ Success:[/] DID created!");
                        AnsiConsole.WriteLine();

                        // Display DID information
                        var table = new Table()
                            .Border(TableBorder.Rounded)
                            .AddColumn(new TableColumn("[bold]Property[/]").Centered())
                            .AddColumn(new TableColumn("[bold]Value[/]"));

                        table.AddRow("DID Identifier", $"[cyan]{result.DidIdentifier}[/]");
                        table.AddRow("Status", $"[green]{result.Status}[/]");
                        table.AddRow("Created At", $"{result.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
                        table.AddRow("Public Key Size", $"{result.PublicKey.Length} bytes");

                        AnsiConsole.Write(table);

                        AnsiConsole.WriteLine();
                        AnsiConsole.MarkupLine("[dim]💡 This DID follows the W3C did:key specification with proper multibase/multicodec encoding[/]");
                    }).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                AnsiConsole.MarkupLine("[yellow]⚠ Operation timed out after 30 seconds[/]");
                Environment.Exit(1);
            }
            catch (InvalidOperationException ex)
            {
                AnsiConsole.MarkupLine($"[red]✗ Operation failed:[/] {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]✗ Unexpected error:[/] {ex.Message}");
                AnsiConsole.MarkupLine("[dim]Check logs for details or contact support[/]");
                Environment.Exit(1);
            }
        });

        var listCommand = new Command("list", "List all DIDs");
        listCommand.SetHandler(async () =>
        {
            try
            {
                await AnsiConsole.Status()
                    .StartAsync("Loading DIDs...", async ctx =>
                    {
                        ctx.Spinner(Spinner.Known.Dots);
                        ctx.SpinnerStyle(Style.Parse("cyan"));

                        // Get database context from DI container
                        using IServiceScope scope = serviceProvider.CreateScope();
                        var dbContext = scope.ServiceProvider.GetRequiredService<HeroSSID.Data.HeroDbContext>();

                        // Query all DIDs from database
                        var dids = await dbContext.Dids
                            .OrderByDescending(d => d.CreatedAt)
                            .Select(d => new
                            {
                                d.DidIdentifier,
                                d.Status,
                                d.CreatedAt
                            })
                            .Take(50) // Limit to 50 most recent
                            .ToListAsync()
                            .ConfigureAwait(false);

                        if (dids.Count == 0)
                        {
                            AnsiConsole.MarkupLine("[yellow]No DIDs found. Create one with:[/] [cyan]herossid did create[/]");
                            return;
                        }

                        // Display DIDs in a formatted table
                        var table = new Table()
                            .Border(TableBorder.Rounded)
                            .AddColumn(new TableColumn("[bold]DID Identifier[/]"))
                            .AddColumn(new TableColumn("[bold]Status[/]").Centered())
                            .AddColumn(new TableColumn("[bold]Created[/]").Centered());

                        foreach (var did in dids)
                        {
                            string statusColor = did.Status?.ToLowerInvariant() == "active" ? "green" : "yellow";
                            table.AddRow(
                                $"[dim]{TruncateDid(did.DidIdentifier)}[/]",
                                $"[{statusColor}]{did.Status}[/]",
                                $"{did.CreatedAt:yyyy-MM-dd HH:mm}");
                        }

                        AnsiConsole.Write(table);
                        AnsiConsole.MarkupLine($"[dim]Showing {dids.Count} most recent DIDs[/]");
                    }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]✗ Failed to list DIDs:[/] {ex.Message}");
                Environment.Exit(1);
            }
        });

        // Helper method to truncate long DIDs for display
        static string TruncateDid(string? did)
        {
            if (string.IsNullOrEmpty(did))
            {
                return "N/A";
            }

            if (did.Length > 60)
            {
                return string.Concat(did.AsSpan(0, 50), "...", did.AsSpan(did.Length - 7));
            }

            return did;
        }

        didCommand.AddCommand(createCommand);
        didCommand.AddCommand(listCommand);

        return didCommand;
    }
}
#pragma warning restore CA1308
#pragma warning restore CA1031
