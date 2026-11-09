using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-controlled, original direct VC2 agent scope signing. Only an issuer
/// with a real matching Ed25519 seed can sign; a Wallet cannot grant rights.
/// Neither issuance nor successful verification is business authorization.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeIssueParameters(
        string? IssuerDid, string? AgentDid, string? Context,
        string? CredentialId, string? Audience, string? Resource,
        string? Action, string? ValidFrom, string? ValidUntil, string? OutputFile);

    internal static bool TryIssueVc2AgentScope(
        Vc2AgentScopeIssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        // All policy comes from the actual issuer operator, not a wallet or
        // subject JSON. No user-provided subject or alternative credential
        // type can bypass the restricted AgentScopeCredential profile.
        if (parameters.IssuerDid is not { Length: > 0 and <= 2048 } issuerDid ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.AgentDid is not { Length: > 0 and <= 2048 } agentDid ||
            !agentDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
            string.IsNullOrEmpty(parameters.Action) ||
            parameters.Action.Length > 64 ||
            !TryCanonicalIssuerHttps(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0 ||
            !TryCanonicalIssuerHttps(parameters.CredentialId, out Uri? credentialId) ||
            !TryCanonicalIssuerHttps(parameters.Audience, out Uri? audience) ||
            !TryCanonicalIssuerHttps(parameters.Resource, out Uri? resource) ||
            resource!.Query.Length != 0 || resource.Fragment.Length != 0 ||
            !DateTimeOffset.TryParseExact(parameters.ValidFrom, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset validFrom) ||
            !DateTimeOffset.TryParseExact(parameters.ValidUntil, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset validUntil) ||
            validFrom.Offset != TimeSpan.Zero ||
            validUntil.Offset != TimeSpan.Zero ||
            validUntil <= validFrom ||
            validUntil - validFrom > TimeSpan.FromMinutes(15))
        {
            return false;
        }

        byte[] seed = [];
        bool outputCreated = false;
        bool completed = false;
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (validFrom > now || validUntil <= now ||
                File.Exists(parameters.OutputFile) ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            string originalJwt;
            try
            {
                originalJwt = Vcdm20AgentScopeAssertion.Create(
                    issuerDid, agentDid, context, credentialId!, audience!,
                    resource, parameters.Action, seed, validFrom, validUntil);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            // Signer's self-check and this independent verifier-policy
            // check both happen BEFORE the artifact becomes visible.
            if (!Vcdm20AgentScopeAssertion.TryVerify(
                    originalJwt, issuerDid, agentDid, context, credentialId!,
                    audience!, resource, parameters.Action, DateTimeOffset.UtcNow,
                    out _))
            {
                return false;
            }

            // The existing private-file helper uses CreateNew and owner-only
            // Unix permissions. Existing files and symlinks are not replaced.
            using (var destination = NewPrivateFile(parameters.OutputFile!))
            {
                outputCreated = true;
                byte[] bytes = Encoding.ASCII.GetBytes(originalJwt + "\n");
                try
                {
                    destination.Write(bytes);
                    destination.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            completed = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or JsonException or
            FormatException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (outputCreated && !completed)
            {
                TryDeletePartialVerifierFile(parameters.OutputFile!);
            }
        }
    }

    private static Command CreateVc2AgentScopeIssueCommand()
    {
        var issuer = Required("--issuer-did", "Issuer-owned Ed25519 did:key, independently enrolled by recipients");
        var agent = Required("--agent", "Exact agent did:key named in the signed statement");
        var context = Required("--context", "Issuer-controlled versioned HTTPS agent scope vocabulary");
        var id = Required("--credential-id", "Signed exact canonical HTTPS credential ID");
        var audience = Required("--audience", "One canonical HTTPS relying-party recipient");
        var resource = Required("--resource", "One exact canonical HTTPS resource, no query or fragment");
        var action = Required("--action", "One exact issuer-approved action, no wildcard");
        var from = Required("--valid-from", "UTC round-trip ISO-8601 start, no future start");
        var until = Required("--valid-until", "UTC round-trip ISO-8601 end, at most 15 minutes after start");
        var output = Required("--output-jwt-file", "New owner-private original JWT file; never overwritten");
        var command = new Command("issue-vc2-agent-scope",
            "Issuer signs one short-lived VC2 agent action assertion with an Ed25519 seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            issuer, agent, context, id, audience, resource, action, from, until, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2AgentScope(new Vc2AgentScopeIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(agent),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(id),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(resource),
                    invocation.ParseResult.GetValueForOption(action),
                    invocation.ParseResult.GetValueForOption(from),
                    invocation.ParseResult.GetValueForOption(until),
                    invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "VC2 agent scope issuance rejected: issuer key, exact scope, signed validity or create-new output invalid. No credential released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer-signed VC2 agent action scope saved. This is ONLY an issuer statement: " +
                "no Agent key control, live status, identity vetting or business authorization.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
