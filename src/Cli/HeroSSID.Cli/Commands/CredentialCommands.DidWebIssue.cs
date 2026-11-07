using System.CommandLine;
using System.CommandLine.Invocation;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline, explicit issuer operation. Only the approved issuer supplies its
/// own private signing seed through redirected standard input.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidWebIssueParameters(
        string? IssuerDid, string? VerificationMethod, string? PublicKeyHex,
        string? IssuerName, string? CredentialId, string? Audience,
        string? HolderDid, string? CredentialType, string? Context,
        string? SubjectFile, string? ValidFrom, string? ValidUntil,
        string? OutputFile);

    internal static bool TryIssueVc2DidWeb(
        Vc2DidWebIssueParameters parameters, Stream seedInput) =>
        throw new NotSupportedException("Test-first: offline issuer CLI is not implemented.");

    private static Command CreateVc2DidWebIssuerCommand()
    {
        var issuer = Required("--issuer-did", "Issuer-approved did:web identity");
        var method = Required("--verification-method", "Issuer-approved did:web #key-1 or #key-2");
        var publicKey = Required("--public-key-hex", "Issuer's enrolled Ed25519 public key");
        var name = Required("--issuer-name", "Issuer's signed descriptive name");
        var id = Required("--credential-id", "Original signed HTTPS credential ID");
        var audience = Required("--audience", "Intended signed HTTPS recipient");
        var holder = Required("--holder", "Holder did:key subject, not proof of control");
        var credentialType = Required("--credential-type", "Issuer-approved credential type");
        var context = Required("--context", "HTTPS subject vocabulary");
        var subject = Required("--subject-file", "Bounded UTF-8 JSON subject file");
        var from = Required("--valid-from", "UTC ISO-8601 validity start");
        var until = Required("--valid-until", "UTC ISO-8601 validity end");
        var output = Required("--output-jwt-file", "New output file, never overwritten");

        var command = new Command("issue-vc2-didweb-recipient",
            "Issue a genuine recipient-bound VC2 JWT with issuer seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            issuer, method, publicKey, name, id, audience, holder,
            credentialType, context, subject, from, until, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2DidWeb(new Vc2DidWebIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(method),
                    invocation.ParseResult.GetValueForOption(publicKey),
                    invocation.ParseResult.GetValueForOption(name),
                    invocation.ParseResult.GetValueForOption(id),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(holder),
                    invocation.ParseResult.GetValueForOption(credentialType),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(subject),
                    invocation.ParseResult.GetValueForOption(from),
                    invocation.ParseResult.GetValueForOption(until),
                    invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine("Issuance rejected: check private seed pipe, signed policy and output; no credential issued.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine("Issuer-signed VC2 JWT saved. Holder control, current status, identity and authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Option<string> Required(string name, string description) =>
        new(name, description) { IsRequired = true };
}
