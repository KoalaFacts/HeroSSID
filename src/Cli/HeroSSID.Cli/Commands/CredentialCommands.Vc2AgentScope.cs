using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline verification of one original issuer-signed VC2 agent scope assertion.
/// No holder control, issuer-to-resource authority or live status is implied.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeVerifyParameters(
        FileInfo? JwtFile, string? TrustedIssuer, string? Agent,
        string? Context, string? CredentialId, string? Audience,
        string? Resource, string? Action);

    internal static bool TryVerifyVc2AgentScope(
        Vc2AgentScopeVerifyParameters parameters, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (string.IsNullOrWhiteSpace(parameters.TrustedIssuer) ||
            !parameters.TrustedIssuer.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.Agent) ||
            !parameters.Agent.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.Action) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0 ||
            !TryCanonicalHttpsPin(parameters.CredentialId, out Uri? id) ||
            !TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !TryCanonicalHttpsPin(parameters.Resource, out Uri? resource) ||
            !TryReadOriginalStatusJwt(parameters.JwtFile, out string originalJwt))
        {
            return false;
        }

        try
        {
            // The whole original signed credential is read only once, with a
            // strict byte bound. Do not accept a detached/rewritten subject.
            return Vcdm20AgentScopeAssertion.TryVerify(
                originalJwt, parameters.TrustedIssuer, parameters.Agent,
                context, id!, audience!, resource!, parameters.Action,
                now, out _);
        }
        catch (Exception exception) when (
            exception is ArgumentException or CryptographicException or
            FormatException or InvalidOperationException or JsonException or
            NotSupportedException)
        {
            return false;
        }
    }

    private static Command CreateVc2AgentScopeCommand()
    {
        var jwt = new Option<FileInfo>("--jwt-file",
            "Original unchanged issuer-signed VC2 JWT") { IsRequired = true };
        var issuer = new Option<string>("--trusted-issuer",
            "Independently enrolled issuer did:key") { IsRequired = true };
        var agent = new Option<string>("--agent",
            "Independently expected agent did:key; not private-key control") { IsRequired = true };
        var context = new Option<string>("--context",
            "Independently approved exact HTTPS vocabulary") { IsRequired = true };
        var id = new Option<string>("--credential-id",
            "Independently pinned signed HTTPS credential ID") { IsRequired = true };
        var audience = new Option<string>("--audience",
            "Independently pinned exact HTTPS recipient") { IsRequired = true };
        var resource = new Option<string>("--resource",
            "Independently authorized exact canonical HTTPS resource") { IsRequired = true };
        var action = new Option<string>("--action",
            "Independently approved one exact action token") { IsRequired = true };
        var command = new Command("verify-vc2-agent-scope",
            "Check genuine Ed25519 issuer signature and exactly pinned short-lived VC2 agent action scope");
        foreach (Option option in new Option[]
        {
            jwt, issuer, agent, context, id, audience, resource, action
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            var parameters = new Vc2AgentScopeVerifyParameters(
                invocation.ParseResult.GetValueForOption(jwt),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(agent),
                invocation.ParseResult.GetValueForOption(context),
                invocation.ParseResult.GetValueForOption(id),
                invocation.ParseResult.GetValueForOption(audience),
                invocation.ParseResult.GetValueForOption(resource),
                invocation.ParseResult.GetValueForOption(action));
            if (!TryVerifyVc2AgentScope(parameters, DateTimeOffset.UtcNow))
            {
                Console.Error.WriteLine(
                    "Agent scope issuer assertion rejected: signature, exact pins, short lifetime, action, resource or file invalid. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer-signed VC2 agent scope, exact single action/resource, recipient, credential ID and short lifetime verified. No claims released. " +
                "Agent private-key possession, real identity, consent, status and business authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
